{ pkgs, lib, ... }:

let
  luksUuid = "87654321-4321-4321-4321-cba987654321";
in
{
  name = "lanzaboote-luks-tpm2-autoenroll";

  globalTimeout = lib.mkForce 600;

  nodes.machine =
    { config, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      system.extraDependencies = [ config.boot.loader.external.installHook ];

      lanzabooteTest = {
        pcrSigningKeyFixture = true;
        persistentRoot = true;
      };

      # The install hook run inside the VM must embed the same PCR 11
      # signatures as the image build did, or the stubs it installs at
      # switch time could never be unsealed. The private key is linked
      # into place at runtime because the module option cannot point into
      # the Nix store.
      boot.lanzaboote.pcrSigning = {
        enable = true;
        privateKeyFile = "/var/lib/lanzaboote-pcr-signing/pcr-private-key.pem";
        publicKeyFile = "${../fixtures/pcr-signing/pcr-public-key.pem}";
      };
      systemd.tmpfiles.settings."10-pcr-signing"."/var/lib/lanzaboote-pcr-signing".L = {
        argument = "${../fixtures/pcr-signing}";
      };

      virtualisation.tpm.enable = true;

      boot.initrd.systemd.enable = true;

      systemd.pcrlock.enable = true;

      virtualisation.emptyDiskImages = [ 64 ];

      boot.initrd.luks.devices.test-crypt = {
        device = "/dev/disk/by-uuid/${luksUuid}";
        # The volume only exists once the test has formatted it, so the
        # device timeout bounds how long the boots before that wait for it.
        crypttabExtraOpts = [
          "tpm2-device=auto"
          "headless=true"
          "nofail"
          "x-systemd.device-timeout=10s"
        ];
      };

      # `nofail` keeps a failed unlock from blocking the boot (the volume
      # does not even exist until the test formats it), but it also drops
      # the generated Before=cryptsetup.target ordering, so the initrd can
      # start shutting down while the unlock attempt is still inside its
      # TPM2 policy session. The `leave-initrd` PCR 11 extend then aborts
      # the session with TPM2_RC_PCR_CHANGED, and switch-root kills the
      # retry. Restore the ordering alone: the initrd waits for the attempt
      # to finish, while a failure still cannot fail the boot.
      boot.initrd.systemd.services."systemd-cryptsetup@test\\x2dcrypt" = {
        overrideStrategy = "asDropin";
        before = [ "cryptsetup.target" ];
      };

      boot.lanzaboote.measuredBoot.autoCryptenroll = {
        enable = true;
        volume = "test-crypt";
      };

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.jq
        pkgs.keyutils
      ];
    };

  testScript =
    { nodes, ... }:
    let
      systemd = nodes.machine.systemd.package;
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      import json

      machine.start()

      with subtest("Prepare the LUKS volume"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed(
          "head -c 32 /dev/urandom > /var/lib/luks-test-key"
          " && chmod 600 /var/lib/luks-test-key"
        )
        machine.succeed(
          "cryptsetup luksFormat --batch-mode"
          " --uuid=${luksUuid}"
          " /dev/vdb /var/lib/luks-test-key"
        )

      with subtest("An absent or locked volume is skipped, not failed"):
        machine.wait_for_unit("auto-cryptenroll.service")
        machine.succeed(
          "journalctl -u auto-cryptenroll -b --no-pager | grep -q 'nothing to enrol'"
        )

      machine.reboot()

      # Unlocking with any non-TPM credential links the volume key into the
      # kernel keyring, exactly as the module's crypttab wiring does for a
      # passphrase typed at boot. The enrolment service turns that linked
      # key into a sharded TPM2 token.
      with subtest("Unlocking the volume enrols a sharded TPM2 token"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed(
          "${systemd}/bin/systemd-cryptsetup attach test-crypt /dev/vdb"
          " /var/lib/luks-test-key"
          " 'link-volume-key=@u::%user:lanzaboote-autoenroll,headless=true'"
        )
        machine.succeed("systemctl restart auto-cryptenroll.service")
        token = json.loads(machine.succeed(
          "cryptsetup luksDump --dump-json-metadata /dev/vdb"
          " | jq -c '[.tokens[] | select(.type == \"systemd-tpm2\")] | first'"
        ))
        assert token["tpm2_pcrlock"] == True, f"token lacks the pcrlock shard: {token}"
        assert token["tpm2_pubkey_pcrs"] == [11], f"token lacks the signed PCR 11 shard: {token}"

      with subtest("The volume key was dropped from the kernel keyring"):
        machine.fail("keyctl search @u user lanzaboote-autoenroll")

      # Enrollment may write EFI variables that shift firmware PCR
      # predictions. Reboot once so the make-policy service re-computes
      # the pcrlock NV index and ESP credential at sysinit (when PCR state
      # is fresh). Then the second boot's initrd can actually unseal.
      machine.reboot()
      with subtest("Policy refreshed after enrolment"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.wait_for_unit("auto-cryptenroll.service")

      machine.reboot()

      with subtest("Initrd unlocked the volume via TPM2, unattended"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -b /dev/mapper/test-crypt")

      with subtest("auto-cryptenroll does not touch a healthy token"):
        machine.wait_for_unit("auto-cryptenroll.service")
        machine.succeed(
          "journalctl -u auto-cryptenroll -b --no-pager | grep -q 'nothing to do'"
        )

      # The TPM2 unlock in the initrd also linked the volume key via the
      # module's crypttab wiring; the no-op service must still drop it.
      with subtest("The volume key was dropped after the no-op run"):
        machine.fail("keyctl search @u user lanzaboote-autoenroll")

      # A removed policy gets a new NV index when re-made, stranding the
      # token enrolled against the old one. Unlocking the volume again is
      # enough for the service to re-enrol, without any stored secret.
      with subtest("A discarded policy heals without manual intervention"):
        old_nv = machine.succeed("jq -r .nvIndex /var/lib/systemd/pcrlock.json").strip()
        machine.succeed(
          "${systemd}/lib/systemd/systemd-pcrlock remove-policy"
        )
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")
        machine.succeed(
          "${systemd}/bin/systemd-cryptsetup attach test-crypt /dev/vdb"
          " /var/lib/luks-test-key"
          " 'link-volume-key=@u::%user:lanzaboote-autoenroll,headless=true'"
        )
        machine.succeed("systemctl restart auto-cryptenroll.service")
        new_nv = machine.succeed("jq -r .nvIndex /var/lib/systemd/pcrlock.json").strip()
        assert new_nv != old_nv, f"remove-policy did not allocate a new NV index: {old_nv}"
        new_nv_handle = machine.succeed("jq -r .nvHandle /var/lib/systemd/pcrlock.json").strip()
        token = json.loads(machine.succeed(
          "cryptsetup luksDump --dump-json-metadata /dev/vdb"
          " | jq -c '[.tokens[] | select(.type == \"systemd-tpm2\")] | first'"
        ))
        assert token["tpm2_pcrlock_nv"] == new_nv_handle, f"token references the wrong NV index: {token}"

      with subtest("Remove the key file so only the TPM2 token can unlock"):
        machine.succeed("rm /var/lib/luks-test-key")

      # Same shape as after the first enrolment: one boot to let the
      # policy settle, then the re-enrolled token must unlock unattended.
      machine.reboot()
      machine.wait_for_unit("systemd-pcrlock-make-policy.service")
      machine.wait_for_unit("auto-cryptenroll.service")
      machine.reboot()

      with subtest("The re-enrolled token unlocks unattended"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -b /dev/mapper/test-crypt")
    '';
}
