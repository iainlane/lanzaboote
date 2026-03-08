{ lib, pkgs, ... }:

{
  name = "lanzaboote-luks-tpm2-initrd";

  nodes.machine =
    { ... }:
    {
      imports = [ ./common/lanzaboote.nix ];

      lanzabooteTest = {
        pcrSigningKeyFixture = true;
        persistentRoot = true;
      };

      virtualisation.tpm.enable = true;

      # Attach a second blank disk that will be formatted as LUKS and unlocked
      # by the initrd on the second boot.
      virtualisation.emptyDiskImages = [ 512 ];

      boot.initrd.systemd.enable = true;

      environment.systemPackages = [
        pkgs.cryptsetup
      ];

      # Specialisation that unlocks /dev/vdb via TPM2 in the initrd and
      # mounts the decrypted volume as /data.
      specialisation.initrd-luks.configuration = {
        boot.initrd.luks.devices = lib.mkVMOverride {
          cryptdata = {
            device = "/dev/vdb";
            crypttabExtraOpts = [ "tpm2-device=auto" ];
          };
        };
        fileSystems."/data" = lib.mkVMOverride {
          device = "/dev/mapper/cryptdata";
          fsType = "ext4";
          options = [ "x-systemd.device-timeout=90s" ];
        };
      };
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

      with subtest("Format /dev/vdb as LUKS"):
        machine.succeed("echo -n testpassphrase | cryptsetup luksFormat --batch-mode --iter-time=1 /dev/vdb -")
        machine.succeed("echo -n testpassphrase | cryptsetup luksOpen /dev/vdb cryptdata")
        machine.succeed("mkfs.ext4 /dev/mapper/cryptdata")
        machine.succeed("mkdir -p /mnt/data && mount /dev/mapper/cryptdata /mnt/data")
        machine.succeed("echo 'initrd-luks-test' > /mnt/data/sentinel")
        machine.succeed("umount /mnt/data")
        machine.succeed("cryptsetup luksClose cryptdata")

      with subtest("Enrol TPM2 key with signed PCR 11 policy"):
        machine.succeed(
          "echo -n testpassphrase | ${systemd}/bin/systemd-cryptenroll "
          "--tpm2-device=auto "
          "--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem "
          "--tpm2-public-key-pcrs=11 "
          "/dev/vdb"
        )

      with subtest("Switch to initrd-luks specialisation"):
        machine.succeed("bootctl set-default nixos-generation-1-specialisation-initrd-luks-\\*.efi")
        machine.succeed("sync")
        machine.crash()

      with subtest("initrd unlocks /dev/vdb via TPM2 and mounts /data"):
        machine.start()
        machine.wait_for_unit("local-fs.target")
        mounts = machine.succeed("mount")
        assert "/dev/mapper/cryptdata on /data type ext4" in mounts, (
          f"/dev/mapper/cryptdata not found in mounts:\n{mounts}"
        )

      with subtest("Data written before reboot is accessible"):
        sentinel = machine.succeed("cat /data/sentinel").strip()
        assert sentinel == "initrd-luks-test", f"Expected 'initrd-luks-test', got '{sentinel}'"
    '';
}
