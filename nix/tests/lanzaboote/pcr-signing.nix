{ pkgs, ... }:

let
  fixturePublicKey = builtins.readFile ../fixtures/pcr-signing/pcr-public-key.pem;
in
{
  name = "lanzaboote-pcr-signing";

  nodes.machine = {
    imports = [ ./common/lanzaboote.nix ];

    lanzabooteTest.pcrSigningKeyFixture = true;

    virtualisation.tpm.enable = true;

    boot.initrd.systemd.enable = true;

    environment.systemPackages = [
      pkgs.bintools-unwrapped
    ];
  };

  testScript =
    { nodes, ... }:
    (import ./common/image-helper.nix { inherit (nodes) machine; })
    + ''
      import json

      machine.start()
      machine.wait_for_unit("default.target")

      with subtest("UKI contains .pcrsig and .pcrpkey PE sections"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        sections = machine.succeed(f"objdump -h {uki_path}")
        print(sections)
        assert ".pcrsig" in sections, f".pcrsig section not found in UKI:\n{sections}"
        assert ".pcrpkey" in sections, f".pcrpkey section not found in UKI:\n{sections}"

      with subtest(".pcrsig section contains valid signed PCR predictions"):
        uki_path = machine.succeed("echo /boot/EFI/Linux/nixos-generation-1-*.efi").strip()
        machine.succeed(f"objcopy -O binary --only-section=.pcrsig {uki_path} /tmp/pcrsig.json")
        pcrsig_raw = machine.succeed("cat /tmp/pcrsig.json")
        pcrsig = json.loads(pcrsig_raw)
        print(json.dumps(pcrsig, indent=2)[:500])
        # systemd-measure sign produces a JSON object with bank names (e.g. "sha256") as keys
        assert isinstance(pcrsig, dict), f"Expected JSON object, got {type(pcrsig)}"
        assert len(pcrsig) > 0, "PCR signature JSON is empty"
        for bank, entries in pcrsig.items():
          assert isinstance(entries, list), f"Expected list for bank {bank}, got {type(entries)}"
          for entry in entries:
            assert "sig" in entry, f"Missing 'sig' field in {bank} entry"
            assert "pol" in entry, f"Missing 'pol' field in {bank} entry"

      with subtest(".pcrpkey section matches fixture public key"):
        machine.succeed(f"objcopy -O binary --only-section=.pcrpkey {uki_path} /tmp/pcrpkey.pem")
        pcrpkey_section = machine.succeed("cat /tmp/pcrpkey.pem")
        assert "BEGIN PUBLIC KEY" in pcrpkey_section, "PE .pcrpkey section is not a valid PEM public key"
        expected_key = """${fixturePublicKey}""".strip()
        actual_key = pcrpkey_section.strip()
        assert actual_key == expected_key, (
          f".pcrpkey section does not match fixture key.\n"
          f"Expected:\n{expected_key}\n"
          f"Actual:\n{actual_key}"
        )

      with subtest("tpm2-pcr-signature.json is delivered via tmpfiles"):
        machine.succeed("test -f /run/systemd/tpm2-pcr-signature.json")
        pcrsig_delivered = machine.succeed("cat /run/systemd/tpm2-pcr-signature.json")
        pcrsig_data = json.loads(pcrsig_delivered)
        assert isinstance(pcrsig_data, dict) and len(pcrsig_data) > 0, "Delivered pcrsig is not valid"

      with subtest("tpm2-pcr-public-key.pem is delivered via tmpfiles"):
        machine.succeed("test -f /run/systemd/tpm2-pcr-public-key.pem")
        pcrpkey = machine.succeed("cat /run/systemd/tpm2-pcr-public-key.pem")
        assert "BEGIN PUBLIC KEY" in pcrpkey, "PCR public key does not look like a PEM file"

      with subtest("ConditionSecurity=measured-uki is satisfied"):
        machine.succeed("systemd-analyze condition ConditionSecurity=measured-uki")
    '';
}
