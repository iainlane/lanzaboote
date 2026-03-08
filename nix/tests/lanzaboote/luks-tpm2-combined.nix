{ pkgs, ... }:

{
  name = "lanzaboote-luks-tpm2-combined";

  nodes.machine =
    { ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest = {
        pcrSigningKeyFixture = true;
        persistentRoot = true;
      };

      virtualisation.tpm.enable = true;

      boot.initrd.systemd.enable = true;

      systemd.pcrlock.enable = true;

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.tpm2-tools
      ];
    };

  testScript =
    { nodes, ... }:
    let
      systemd = nodes.machine.systemd.package;
    in
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      machine.start()

      with subtest("PCR signature and public key are delivered"):
        machine.succeed("test -f /run/systemd/tpm2-pcr-signature.json")
        machine.succeed("test -f /run/systemd/tpm2-pcr-public-key.pem")

      with subtest("pcrlock services succeeded"):
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        machine.succeed("test -f /var/lib/systemd/pcrlock.json")

      with subtest("Create a LUKS volume"):
        machine.succeed("dd if=/dev/zero of=/root/luks.img bs=1M count=32")
        loop_dev = machine.succeed("losetup --find --show /root/luks.img").strip()
        machine.succeed(f"echo -n testpassphrase | cryptsetup luksFormat --batch-mode {loop_dev} -")

      with subtest("Unlock fails without any TPM2 token"):
        machine.fail(
          f"${systemd}/bin/systemd-cryptsetup attach fail-crypt {loop_dev} - tpm2-device=auto"
        )

      with subtest("Enrol TPM2 with signed PCR 11 only"):
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--tpm2-device=auto "
          f"--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem "
          f"--tpm2-public-key-pcrs=11 "
          f"{loop_dev}"
        )

      with subtest("Signed PCR 11 only token works"):
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")

      with subtest("Wipe PCR-only token and enrol combined sharded token"):
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--wipe-slot=tpm2 {loop_dev}"
        )
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--tpm2-device=auto "
          f"--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem "
          f"--tpm2-public-key-pcrs=11 "
          f"--tpm2-pcrlock=/var/lib/systemd/pcrlock.json "
          f"{loop_dev}"
        )

      with subtest("Combined token unlocks successfully (both shards unseal)"):
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")

      with subtest("Invalidating pcrlock NV index breaks combined unlock"):
        machine.succeed("${systemd}/lib/systemd/systemd-pcrlock remove-policy")
        machine.fail(
          f"${systemd}/bin/systemd-cryptsetup attach fail-crypt {loop_dev} - tpm2-device=auto"
        )

      with subtest("Restoring pcrlock policy re-enables combined unlock"):
        machine.succeed("${systemd}/lib/systemd/systemd-pcrlock make-policy --recovery-pin=no")
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")

      with subtest("Corrupting PCR 11 breaks combined unlock"):
        machine.succeed("tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000")
        machine.fail(
          f"${systemd}/bin/systemd-cryptsetup attach fail-crypt {loop_dev} - tpm2-device=auto"
        )

      with subtest("Combined unlock works after reboot"):
        machine.reboot()
        machine.wait_for_unit("systemd-pcrlock-make-policy.service")
        loop_dev = machine.succeed("losetup --find --show /root/luks.img").strip()
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")
    '';
}
