{ pkgs, ... }:

{
  name = "lanzaboote-luks-tpm2";

  nodes.machine =
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest = {
        pcrSigningKeyFixture = true;
        persistentRoot = true;
      };

      virtualisation.tpm.enable = true;

      environment.systemPackages = [
        pkgs.cryptsetup
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

      with subtest("Create a LUKS volume on a loop device"):
        machine.succeed("dd if=/dev/zero of=/root/luks.img bs=1M count=32")
        loop_dev = machine.succeed("losetup --find --show /root/luks.img").strip()
        machine.succeed(f"echo -n testpassphrase | cryptsetup luksFormat --batch-mode {loop_dev} -")

      with subtest("Volume is genuinely encrypted"):
        machine.succeed(f"cryptsetup isLuks {loop_dev}")
        raw_data = machine.succeed(f"dd if={loop_dev} bs=4096 skip=1024 count=16 2>/dev/null | od -A x -t x1z | head -20")
        print(raw_data)

      with subtest("Volume cannot be opened without any keyslot"):
        machine.fail(
          f"${systemd}/bin/systemd-cryptsetup attach fail-crypt {loop_dev} - tpm2-device=auto"
        )

      with subtest("Enrol TPM2 key with signed PCR 11 policy"):
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--tpm2-device=auto "
          f"--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem "
          f"--tpm2-public-key-pcrs=11 "
          f"{loop_dev}"
        )

      with subtest("Unlock LUKS volume via TPM2 without passphrase"):
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")

      with subtest("Encrypted volume is usable"):
        machine.succeed("mkfs.ext4 /dev/mapper/test-crypt")
        machine.succeed("mkdir -p /mnt/test && mount /dev/mapper/test-crypt /mnt/test")
        machine.succeed("echo 'luks-test-data' > /mnt/test/sentinel")
        machine.succeed("umount /mnt/test")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")

      with subtest("Passphrase-only unlock still fails via TPM2 after wipe"):
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--wipe-slot=tpm2 {loop_dev}"
        )
        machine.fail(
          f"${systemd}/bin/systemd-cryptsetup attach fail-crypt {loop_dev} - tpm2-device=auto"
        )

      with subtest("Re-enrol TPM2 and verify data survives"):
        machine.succeed(
          f"echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          f"--tpm2-device=auto "
          f"--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem "
          f"--tpm2-public-key-pcrs=11 "
          f"{loop_dev}"
        )

      with subtest("TPM2 unlock works after reboot"):
        machine.reboot()
        loop_dev = machine.succeed("losetup --find --show /root/luks.img").strip()
        machine.succeed(
          f"${systemd}/bin/systemd-cryptsetup attach test-crypt {loop_dev} - tpm2-device=auto"
        )
        machine.succeed("test -b /dev/mapper/test-crypt")
        machine.succeed("mkdir -p /mnt/test && mount /dev/mapper/test-crypt /mnt/test")
        sentinel = machine.succeed("cat /mnt/test/sentinel").strip()
        assert sentinel == "luks-test-data", f"Expected 'luks-test-data', got '{sentinel}'"
        machine.succeed("umount /mnt/test")
        machine.succeed("${systemd}/bin/systemd-cryptsetup detach test-crypt")
    '';
}
