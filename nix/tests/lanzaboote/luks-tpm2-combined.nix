{ pkgs, lib, ... }:

let
  luksUuid = "12345678-1234-1234-1234-123456789abc";
in
{
  name = "lanzaboote-luks-tpm2-combined";

  globalTimeout = lib.mkForce 600;

  nodes.machine =
    { config, ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      # A second generation whose stub differs from gen1 (the extra kernel
      # parameter changes the .cmdline section and therefore the PE hash),
      # used to prove that unlock survives a switch to a new boot stack.
      specialisation.gen2.configuration = {
        boot.kernelParams = [ "lanzaboote.test-gen2" ];
      };

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

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.tpm2-tools
      ];
    };

  testScript =
    { nodes, ... }:
    let
      systemd = nodes.machine.systemd.package;
      installHook = nodes.machine.boot.loader.external.installHook;
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      machine.start()

      with subtest("PCR signature and public key are delivered"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -f /run/systemd/tpm2-pcr-signature.json")
        machine.succeed("test -f /run/systemd/tpm2-pcr-public-key.pem")

      with subtest("pcrlock services succeeded"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("pcrlock credential written to ESP"):
        machine.succeed("test -d /boot/loader/credentials")
        machine.succeed("ls /boot/loader/credentials/pcrlock.*.cred")

      with subtest("Format LUKS volume and enrol combined TPM2 token"):
        machine.succeed("echo -n testpassphrase > /tmp/luks-key && chmod 600 /tmp/luks-key")
        machine.succeed(
          "cryptsetup luksFormat --batch-mode"
          " --uuid=${luksUuid}"
          " /dev/vdb /tmp/luks-key"
        )
        # systemd-cryptenroll auto-detects pcrlock when an NV index
        # exists, creating a sharded token (signed PCR 11 + pcrlock).
        machine.succeed(
          "${systemd}/bin/systemd-cryptenroll"
          " --unlock-key-file=/tmp/luks-key"
          " --tpm2-device=auto"
          " --tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem"
          " --tpm2-public-key-pcrs=11"
          " /dev/vdb"
        )

      # Enrollment may write EFI variables that shift firmware PCR
      # predictions.  Reboot once so the vendor make-policy service
      # re-computes the pcrlock NV index and ESP credential at sysinit
      # (when PCR state is fresh).  Then the second boot's initrd can
      # actually unseal.

      machine.reboot()
      with subtest("Policy refreshed after enrollment"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")

      machine.reboot()

      with subtest("Initrd unlocked LUKS volume via TPM2 after reboot"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("test -b /dev/mapper/test-crypt")

      # The scenario that matters most for unattended systems: a switch to a
      # new generation must roll the policy forward before the reboot, so
      # the next boot unlocks without re-enrolment, without removing the
      # policy, and without any manual service restarts.
      with subtest("Switching to a new generation rolls the policy forward"):
        machine.succeed("${installHook}")
        machine.succeed(
          "bootctl set-default nixos-generation-1-specialisation-gen2-\*.efi"
        )
        machine.succeed("sync")

      machine.reboot()

      with subtest("Initrd unlocked LUKS volume after switching generations"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("grep -q lanzaboote.test-gen2 /proc/cmdline")
        machine.succeed("test -b /dev/mapper/test-crypt")

      with subtest("Runtime TPM2 unlock matches the measured boot phases"):
        # The device only supports one mapping at a time, so release the
        # one the initrd created before attaching again at runtime, where
        # the later boot phases have been measured into PCR 11.
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")
        machine.succeed(
          "${systemd}/bin/systemd-cryptsetup attach test-crypt /dev/vdb -"
          " tpm2-device=auto,headless=true"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")

      # Extending a covered PCR outside systemd bypasses the event log, so
      # the live PCR state no longer matches it. Policy generation works
      # from the component files, not the live state, so a switch in this
      # situation still succeeds.
      with subtest("Switching with drifted PCR state still succeeds"):
        machine.succeed(
          "tpm2_pcrextend 11:sha256="
          "0000000000000000000000000000000000000000000000000000000000000000"
        )
        machine.succeed("${installHook}")

      # PCR 11 no longer carries any value the PCR signing key signed, so
      # the signed-policy shard refuses to unseal until a reboot restores
      # the measured state.
      with subtest("Corrupting PCR 11 breaks TPM2 unlock"):
        machine.fail(
          "${systemd}/bin/systemd-cryptsetup attach test-crypt-check /dev/vdb -"
          " tpm2-device=auto,headless=true"
        )
    '';
}
