{
  lib,
  config,
  options,
  pkgs,
  ...
}:
let
  cfg = config.boot.lanzaboote;
  espMountPoint = config.boot.loader.efi.efiSysMountPoint;

  loaderSettingsFormat = pkgs.formats.keyValue {
    mkKeyValue = k: v: if v == null then "" else lib.generators.mkKeyValueDefault { } " " k v;
  };

  loaderConfigFile = loaderSettingsFormat.generate "loader.conf" cfg.settings;

  configurationLimit = if cfg.configurationLimit == null then 0 else cfg.configurationLimit;

  efiSysMountPoints = [
    espMountPoint
  ]
  ++ cfg.extraEfiSysMountPoints;

  mkInstallCommand =
    efiSysMountPoint:
    ''
      PATH=${config.systemd.package}/lib/systemd:$PATH
      ${cfg.installCommand} \
    ''
    + (
      lib.escapeShellArgs (
        [
          "--public-key=${toString cfg.publicKeyFile}"
          "--private-key=${toString cfg.privateKeyFile}"
        ]
        # The PCR signing keys are passed here rather than in
        # `installCommand` so that image builds can supply their own
        # build-time keys: the configured private key is an external path
        # that only exists on the running system.
        ++ lib.optionals cfg.pcrSigning.enable [
          "--pcr-private-key=${toString cfg.pcrSigning.privateKeyFile}"
          "--pcr-public-key=${toString cfg.pcrSigning.publicKeyFile}"
        ]
        ++ lib.optionals (cfg.measuredBoot.enable && pcr 4) [
          "--pcrlock-directory=${cfg.measuredBoot.pcrlockDirectory}"
        ]
        ++ [
          efiSysMountPoint
        ]
      )
      + " /nix/var/nix/profiles/system-*-link"
    );

  installHook = pkgs.writeShellScriptBin "lzbt" (
    ''
      set -euo pipefail

      ${lib.concatStringsSep "\n" (map mkInstallCommand efiSysMountPoints)}
    ''
    + lib.optionalString cfg.measuredBoot.enable ''
      echo "Predicting the PCR state for future boots..."
      ${makePolicyCommand}
    ''
    # Generate pcrlock predictions for the boot loader and all installed
    # thin stubs.  Component IDs follow the well-known numbering from
    # systemd.pcrlock(5): 640 for the boot loader PE (PCR 4) and 650 for
    # each boot entry's thin stub (PCR 4 + PCR 11).  These sit in the
    # standard range covered by the vendor make-policy --location=770.
    + lib.optionalString config.systemd.pcrlock.enable ''
      boot_loader_pcrlock_dir="/var/lib/pcrlock.d/640-boot-loader.pcrlock.d"
      boot_entry_pcrlock_dir="/var/lib/pcrlock.d/650-boot-entry.pcrlock.d"
      global_sysext_pcrlock_dir="/var/lib/pcrlock.d/655-global-sysext.pcrlock.d"
      mkdir -p "$boot_loader_pcrlock_dir" "$boot_entry_pcrlock_dir" "$global_sysext_pcrlock_dir"
      declare -A current_boot_loader_hashes
      declare -A current_boot_entry_hashes
      declare -A current_global_sysext_hashes

      # Back up the component directories so a failure below cannot leave
      # a half-updated set of predictions behind: the policy must be built
      # either from the complete old set or the complete new set.
      pcrlock_backup="$(mktemp -d)"
      cp -a "$boot_loader_pcrlock_dir" "$boot_entry_pcrlock_dir" "$global_sysext_pcrlock_dir" "$pcrlock_backup/"
      restore_pcrlock_components() {
        echo "error: pcrlock prediction update failed; restoring previous components." >&2
        echo "error: the TPM2 policy was not updated, so the next boot may ask for the fallback passphrase." >&2
        rm -rf "$boot_loader_pcrlock_dir" "$boot_entry_pcrlock_dir" "$global_sysext_pcrlock_dir"
        cp -a "$pcrlock_backup/640-boot-loader.pcrlock.d" "$boot_loader_pcrlock_dir"
        cp -a "$pcrlock_backup/650-boot-entry.pcrlock.d" "$boot_entry_pcrlock_dir"
        cp -a "$pcrlock_backup/655-global-sysext.pcrlock.d" "$global_sysext_pcrlock_dir"
        rm -rf "$pcrlock_backup"
      }
      trap restore_pcrlock_components ERR

      lock_failed=0

      # lock-boot-loader discovers the bootloader, computes the PE hash,
      # skips if the output already exists, and prints the hash to stdout.
      if hash="$(${lib.getExe cfg.package} lock-boot-loader \
        --systemd ${config.systemd.package} \
        --esp "${espMountPoint}" \
        --pcrlock "$boot_loader_pcrlock_dir")"; then
        current_boot_loader_hashes["$hash"]=1
      else
        lock_failed=1
        echo "warning: systemd-boot pcrlock generation failed" >&2
      fi

      # Generate PCR 4 + PCR 11 variants for all lanzaboote thin stubs.
      for stub in "${espMountPoint}/EFI/Linux/nixos-"*".efi"; do
        [ -f "$stub" ] || continue
        if hash="$(${lib.getExe cfg.package} lock-thin-stub \
          --systemd ${config.systemd.package} \
          --esp "${espMountPoint}" \
          --pcrlock "$boot_entry_pcrlock_dir" \
          "$stub")"; then
          current_boot_entry_hashes["$hash"]=1
        else
          lock_failed=1
          echo "warning: thin-stub pcrlock generation failed for $stub" >&2
        fi
      done

      # Predict the PCR 13 measurement of the global system extensions.
      # No output means the boot partition carries none, and nothing needs
      # to be predicted.
      if hash="$(${lib.getExe cfg.package} lock-sysexts \
        --systemd ${config.systemd.package} \
        --esp "${espMountPoint}" \
        --pcrlock "$global_sysext_pcrlock_dir")"; then
        if [ -n "$hash" ]; then
          current_global_sysext_hashes["$hash"]=1
        fi
      else
        lock_failed=1
        echo "warning: global sysext pcrlock generation failed" >&2
      fi

      # Only garbage-collect when every lock command succeeded: a transient
      # failure must not delete variants for binaries that are still
      # installed. gc-pcrlock additionally retains variants whose digests
      # appear in the current TPM event log, so the booted state stays
      # recognised by the policy even after its binary leaves the ESP.
      if [ "$lock_failed" -eq 0 ]; then
        keep_boot_loader=()
        for hash in "''${!current_boot_loader_hashes[@]}"; do
          keep_boot_loader+=(--keep "$hash")
        done
        ${lib.getExe cfg.package} gc-pcrlock \
          --systemd ${config.systemd.package} \
          --pcrlock "$boot_loader_pcrlock_dir" \
          "''${keep_boot_loader[@]}"

        keep_boot_entry=()
        for hash in "''${!current_boot_entry_hashes[@]}"; do
          keep_boot_entry+=(--keep "$hash")
        done
        ${lib.getExe cfg.package} gc-pcrlock \
          --systemd ${config.systemd.package} \
          --pcrlock "$boot_entry_pcrlock_dir" \
          "''${keep_boot_entry[@]}"

        keep_global_sysext=()
        for hash in "''${!current_global_sysext_hashes[@]}"; do
          keep_global_sysext+=(--keep "$hash")
        done
        ${lib.getExe cfg.package} gc-pcrlock \
          --systemd ${config.systemd.package} \
          --pcrlock "$global_sysext_pcrlock_dir" \
          "''${keep_global_sysext[@]}"
      fi

      # Remove empty directories to avoid zeroing predictions
      if [ -z "$(ls -A "$boot_loader_pcrlock_dir" 2>/dev/null)" ]; then
        rmdir "$boot_loader_pcrlock_dir" 2>/dev/null || true
      fi
      if [ -z "$(ls -A "$boot_entry_pcrlock_dir" 2>/dev/null)" ]; then
        rmdir "$boot_entry_pcrlock_dir" 2>/dev/null || true
      fi
      if [ -z "$(ls -A "$global_sysext_pcrlock_dir" 2>/dev/null)" ]; then
        rmdir "$global_sysext_pcrlock_dir" 2>/dev/null || true
      fi

      # Update the NV index and ESP credential so the next boot can unlock.
      # Updating the NV index first unseals the recovery PIN under the old
      # policy, so the old policy must be satisfiable here, at switch time.
      # The firmware PCRs it covers are stable for the entire boot, so the
      # update can run at any point. The boot-time make-policy service is
      # overridden to run the same command, so the two writers never
      # rewrite each other's prediction.
      ${combinedMakePolicyCommand}

      trap - ERR
      rm -rf "$pcrlock_backup"
    ''
  );

  format = pkgs.formats.yaml { };
  sbctlConfigFile = format.generate "sbctl.conf" {
    keydir = "${cfg.pkiBundle}/keys";
    guid = "${cfg.pkiBundle}/GUID";
  };

  json = pkgs.formats.json { };

  pcr = n: lib.elem n cfg.measuredBoot.pcrs;

  staticMeasurements = pkgs.runCommand "pcrlock.d" { preferLocalBuild = true; } ''
    mkdir -p $out

    for f in ${toString cfg.measuredBoot.upstreamStaticMeasurements}; do
      mkdir -p $(dirname $out/$f)
      ln -sf ${config.systemd.package}/lib/pcrlock.d/$f $out/$f
    done

    ${lib.concatLines (
      lib.mapAttrsToList (n: v: "ln -s ${v.source} $out/${n}.pcrlock") cfg.measuredBoot.staticMeasurements
    )}
  '';

  # Shared by the install hook, the boot-time make-policy unit, and the
  # fwupd re-lock service, so every writer of the policy produces the same
  # prediction. See the pcrlockPcrs option for why PCR 11 is not covered.
  combinedMakePolicyCommand = lib.escapeShellArgs (
    [
      "${config.systemd.package}/lib/systemd/systemd-pcrlock"
      "make-policy"
    ]
    ++ lib.map (pcr: "--pcr=${toString pcr}") cfg.pcrlockPcrs
  );

  makePolicyCommand = lib.escapeShellArgs (
    [
      "${config.systemd.package}/lib/systemd/systemd-pcrlock"
      "make-policy"
      "--components=${staticMeasurements}"
      "--components=${cfg.measuredBoot.pcrlockDirectory}"
      "--policy=${cfg.measuredBoot.pcrlockPolicy}"
      "--location=770"
    ]
    ++ lib.map (pcr: "--pcr=${toString pcr}") cfg.measuredBoot.pcrs
  );

  autoCryptenrollCfg = cfg.measuredBoot.autoCryptenroll;

  autoCryptenrollDevice =
    if autoCryptenrollCfg.volume != null then
      config.boot.initrd.luks.devices.${autoCryptenrollCfg.volume}.device
    else
      autoCryptenrollCfg.device;

  # The kernel keyring description under which the unlocked volume key is
  # linked, shared between the crypttab entry that links it and the
  # enrolment service that consumes it.
  volumeKeyDescription = "lanzaboote-autoenroll";

  autoCryptenrollScript = pkgs.writeShellApplication {
    name = "lanzaboote-auto-cryptenroll";

    runtimeInputs = [
      config.systemd.package
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.jq
      pkgs.keyutils
    ];

    text = ''
      device=${lib.escapeShellArg (toString autoCryptenrollDevice)}
      vk_desc=${lib.escapeShellArg volumeKeyDescription}

      tmp_keyfile=""

      cleanup() {
        if [ -n "$tmp_keyfile" ] && [ -e "$tmp_keyfile" ]; then
          cryptsetup luksRemoveKey "$device" "$tmp_keyfile" || true
          rm -f "$tmp_keyfile"
        fi

        # The volume key only needs to stay in the keyring long enough for
        # enrolment. Drop it whether or not it was used.
        key_id=$(keyctl search @u user "$vk_desc" 2>/dev/null) || return 0
        keyctl unlink "$key_id" @u || true
      }
      trap cleanup EXIT

      if [ ! -e "$device" ]; then
        echo "$device does not exist, nothing to enrol."
        exit 0
      fi

      tokens() {
        cryptsetup luksDump --dump-json-metadata "$device" \
          | jq '[.tokens[]? | select(.type == "systemd-tpm2")]'
      }

      unlocked() {
        resolved=$(readlink -f "$device")
        holders=/sys/class/block/$(basename "$resolved")/holders
        [ -n "$(ls -A "$holders" 2>/dev/null)" ]
      }

      keyring_has_volume_key() {
        keyctl search @u user "$vk_desc" >/dev/null 2>&1
      }

      # A token is only usable if it references the NV index of the current
      # policy: removing and re-making the policy allocates a new index and
      # strands any token enrolled against the old one. The token records
      # the policy's nvHandle verbatim at enrolment time.
      healthy() {
        expected_nv=$(jq -r '.nvHandle // empty' ${cfg.measuredBoot.pcrlockPolicy} 2>/dev/null || true)
        [ -n "$expected_nv" ] || return 1
        tokens | jq -e --arg nv "$expected_nv" '
          [.[] | (.tpm2_pcrlock == true) and (.tpm2_pcrlock_nv == $nv)${lib.optionalString cfg.pcrSigning.enable " and (.tpm2_pubkey_pcrs == [11])"}] | any
        ' >/dev/null
      }

      # When the boot-time policy update failed, the policy in the NV index
      # can no longer authorise its own replacement; PCR state has drifted
      # outside anything that was predicted, and the recovery PIN is sealed
      # behind the same policy. The volume key is the stronger credential:
      # whoever could unlock the volume may discard the dead policy and
      # start afresh.
      policy_stuck=""
      if systemctl is-failed --quiet systemd-pcrlock-make-policy.service 2>/dev/null; then
        policy_stuck=1
      fi

      if [ -z "$policy_stuck" ] && healthy; then
        echo "$device already has a TPM2 token with the expected policy shards, nothing to do."
        exit 0
      fi

      if [ -n "$policy_stuck" ]; then
        if ! keyring_has_volume_key; then
          echo "The boot-time pcrlock policy update failed and no volume key is available to reset it." >&2
          echo "Unlock $device with a passphrase or key file during boot to recover automatically." >&2
          exit 1
        fi

        echo "The boot-time pcrlock policy update failed; discarding the stale policy and starting afresh."
        ${config.systemd.package}/lib/systemd/systemd-pcrlock remove-policy || true
      fi

      # Refresh the artifacts on the ESP and the pcrlock policy, so the
      # enrolment binds to the boot stack as it is now.
      ${installHook}/bin/lzbt

      if [ -z "$policy_stuck" ] && healthy; then
        echo "The TPM2 token on $device matches the refreshed policy, nothing to do."
        exit 0
      fi

      enroll_args=(
        --wipe-slot=tpm2
        --tpm2-device=auto
        --tpm2-pcrlock=${cfg.measuredBoot.pcrlockPolicy}
      )
      ${lib.optionalString cfg.pcrSigning.enable ''
        enroll_args+=(
          --tpm2-public-key=${lib.escapeShellArg (toString cfg.pcrSigning.publicKeyFile)}
          --tpm2-public-key-pcrs=11
        )
      ''}

      enroll() {
        systemd-cryptenroll "$1" "''${enroll_args[@]}" "$device"
      }

      if [ -z "$policy_stuck" ] && tokens | jq -e 'length > 0' >/dev/null && enroll --unlock-tpm2-device=auto; then
        echo "Re-enrolled the TPM2 token on $device using the existing enrolment."
      elif ! unlocked && ! keyring_has_volume_key; then
        # A locked volume holds no credential to enrol with; the next boot
        # that unlocks it will enrol.
        echo "$device is not unlocked, nothing to enrol from."
        exit 0
      elif keyring_has_volume_key; then
        # The volume key was linked into the kernel keyring when the volume
        # was unlocked earlier in this boot. systemd-cryptenroll cannot read
        # it from there, so mint a transient key slot with it and enrol
        # through that.
        tmp_keyfile=$(mktemp /run/lanzaboote-auto-cryptenroll.XXXXXX)
        head -c 32 /dev/urandom >"$tmp_keyfile"
        cryptsetup luksAddKey --volume-key-keyring "%user:$vk_desc" "$device" "$tmp_keyfile"

        enroll --unlock-key-file="$tmp_keyfile"
        echo "Enrolled a TPM2 token on $device using the volume key from the kernel keyring."
      else
        echo "$device is unlocked, but its volume key was not linked into the kernel keyring." >&2
        echo "Check the link-volume-key option on its crypttab entry, or run systemd-cryptenroll manually." >&2
        exit 1
      fi

      ${lib.optionalString autoCryptenrollCfg.autoReboot "systemctl reboot"}
    '';
  };
in
{
  imports = [
    (lib.mkRemovedOptionModule [ "boot" "lanzaboote" "enrollKeys" ] ''
      Removed this internal option intended for testing only without replacement.
    '')
  ];

  options.boot.lanzaboote = {
    enable = lib.mkEnableOption "Lanzaboote, a secure boot tool for NixOS";

    configurationLimit = lib.mkOption {
      default = config.boot.loader.systemd-boot.configurationLimit;
      defaultText = "config.boot.loader.systemd-boot.configurationLimit";
      example = 120;
      type = lib.types.nullOr lib.types.int;
      description = ''
        Maximum number of latest generations in the boot menu.
        Useful to prevent boot partition running out of disk space.

        `null` means no limit i.e. all generations
        that were not garbage collected yet.
      '';
    };

    pkiBundle = lib.mkOption {
      type = lib.types.nullOr lib.types.externalPath;
      description = "PKI bundle containing db, PK, KEK";
    };

    publicKeyFile = lib.mkOption {
      type = lib.types.path;
      default = "${cfg.pkiBundle}/keys/db/db.pem";
      defaultText = "\${config.boot.lanzaboote.pkiBundle}/keys/db/db.pem";
      description = "Public key to sign your boot files";
    };

    privateKeyFile = lib.mkOption {
      type = lib.types.path;
      default = "${cfg.pkiBundle}/keys/db/db.key";
      defaultText = "\${config.boot.lanzaboote.pkiBundle}/keys/db/db.key";
      description = "Private key to sign your boot files";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.lzbt;
      defaultText = lib.literalExpression "pkgs.lzbt";
      description = "Lanzaboote tool (lzbt) package";
    };

    settings = lib.mkOption {
      type = lib.types.submodule {
        freeformType = loaderSettingsFormat.type;
      };

      apply = lib.recursiveUpdate options.boot.lanzaboote.settings.default;

      default = {
        timeout = config.boot.loader.timeout;
        console-mode = config.boot.loader.systemd-boot.consoleMode;
        editor = config.boot.loader.systemd-boot.editor;
        default = "nixos-*";
      }
      // lib.optionalAttrs cfg.autoEnrollKeys.enable {
        secure-boot-enroll = "force";
      };

      defaultText = ''
        {
          timeout = config.boot.loader.timeout;
          console-mode = config.boot.loader.systemd-boot.consoleMode;
          editor = config.boot.loader.systemd-boot.editor;
          default = "nixos-*";
        }
        // lib.optionalAttrs config.boot.lanzaboote.autoEnrollKeys.enable {
          secure-boot-enroll = "force";
        };
      '';

      example = lib.literalExpression ''
        {
          editor = null; # null value removes line from the loader.conf
          beep = true;
          default = "@saved";
          timeout = 10;
        }
      '';

      description = ''
        Configuration for the `systemd-boot`

        See `loader.conf(5)` for supported values.
      '';
    };

    sortKey = lib.mkOption {
      default = "lanza";
      type = lib.types.str;
      description = ''
        The sort key used for the NixOS bootloader entries. This key determines
        sorting relative to non-NixOS entries. See also
        https://uapi-group.org/specifications/specs/boot_loader_specification/#sorting
      '';
    };

    bootCounting = {
      initialTries = lib.mkOption {
        type = lib.types.ints.u32;
        default = 0;
        description = ''
          The number of boot counting tries to set for new boot entries.
          Setting this to zero, disables boot counting.
          See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
        '';
      };
    };

    pcrSigning = {
      enable = lib.mkEnableOption "PCR 11 signing for measured boot";
      privateKeyFile = lib.mkOption {
        type = lib.types.externalPath;
        description = ''
          Private key for signing PCR 11 predictions.
        '';
      };
      publicKeyFile = lib.mkOption {
        type = lib.types.path;
        description = ''
          Public key for PCR 11 signature verification. Embedded in the UKI
          as a .pcrpkey PE section.
        '';
      };
    };

    fwupd = {
      autoUnlockFirmwareCode = lib.mkEnableOption "" // {
        description = ''
          Whether to automatically relax the pcrlock firmware-code component
          when fwupd stages a UEFI capsule update.
        '';
        default = true;
      };
    };

    pcrlockPcrs = lib.mkOption {
      type = lib.types.listOf (
        lib.types.enum [
          0
          1
          2
          3
          4
          5
          7
          13
          14
          15
        ]
      );
      default = [
        0
        1
        2
        3
        4
        7
        13
        15
      ];
      description = ''
        PCRs the systemd-pcrlock policy covers when `systemd.pcrlock.enable`
        drives the install hook.

        PCR 11 is intentionally not allowed here: systemd-pcrlock refuses
        policies with more than eight alternative values per PCR, and PCR 11
        takes one predicted value per boot entry and boot phase, so covering
        it would limit the ESP to two generations. Bind PCR 11 through the
        signed policy shard (`pcrSigning`) instead, which keeps working
        however many generations are installed.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "info"
        "debug"
      ];
      default = "info";
      description = ''
        Log level of lzbt.
      '';
    };

    installCommand = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      description = ''
        The partial command to execute lzbt install. This can be used to build
        images by adding the directory to install to and the path to the
        toplevel.
      '';
      default = ''
        # Use the system from the kernel's hostPlatform because this should
        # always, even in the cross compilation case, be the right system.
        ${lib.getExe cfg.package} ${lib.optionalString (cfg.logLevel == "debug") "-vv"} install \
          --system ${config.boot.kernelPackages.stdenv.hostPlatform.system} \
          --systemd ${config.systemd.package} \
          --systemd-boot-loader-config ${loaderConfigFile} \
          --configuration-limit ${toString configurationLimit} \
          --allow-unsigned ${lib.boolToString cfg.allowUnsigned} \
          --bootcounting-initial-tries ${toString cfg.bootCounting.initialTries}'';
      defaultText = lib.literalExpression ''
        ''${lib.getExe config.boot.lanzaboote.package} ''${lib.optionalString (config.boot.lanzaboote.logLevel == "debug") "-vv"} install \
          --system ''${config.boot.kernelPackages.stdenv.hostPlatform.system} \
          --systemd ''${config.systemd.package} \
          --systemd-boot-loader-config ''${loaderConfigFile} \
          --configuration-limit ''${toString configurationLimit} \
          --allow-unsigned ''${lib.boolToString config.boot.lanzaboote.allowUnsigned} \
          --bootcounting-initial-tries ''${toString config.boot.lanzaboote.bootCounting.initialTries}'';
    };

    extraEfiSysMountPoints = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = ''
        List of EFI system partition mount points to install the bootloader to (additionally to boot.loader.efi.efiSysMountPoint).
      '';
      default = [ ];
    };

    allowUnsigned = lib.mkEnableOption "" // {
      description = ''
        Whether to allow installing unsigned artifacts to the ESP.

        This is useful for installing Lanzaboote where the key is generated during the first boot.
      '';
      default = cfg.autoGenerateKeys.enable;
      defaultText = "config.boot.lanzaboote.autoGenerateKeys.enable";
    };

    autoGenerateKeys = {
      enable = lib.mkEnableOption "automatically generating Secure Boot keys if they do not exist";
    };

    autoEnrollKeys = {
      enable = lib.mkEnableOption "" // {
        description = "Whether to automatically enroll the Secure Boot keys.";
      };

      autoReboot = lib.mkEnableOption "" // {
        description = ''
          Whether to automatically reboot after preparing the keys for auto enrollment.

          Enable this to enroll the keys via systemd-boot into the firmware
          right after they have been provisioned without waiting for a manual reboot.
        '';
      };

      includeMicrosoftKeys = lib.mkEnableOption "" // {
        description = "Whether to include Microsoft keys when enrolling the Secure Boot keys.";
        default = true;
      };

      includeChecksumsFromTPM = lib.mkEnableOption "" // {
        description = "Whether to include checksums from the TPM Eventlog when enrolling the Secure Boot keys.";
      };

      allowBrickingMyMachine = lib.mkEnableOption "" // {
        description = ''
          Whether to ignore option ROM signatures when enrolling the Secure
          Boot keys. This might brick your machine. Be sure you know what
          you're doing before enabling this.

          See <https://github.com/Foxboron/sbctl/wiki/FAQ#option-rom> for more
          details.
        '';
      };
    };

    measuredBoot = {
      enable = lib.mkEnableOption "Measured Boot";

      pcrs = lib.mkOption {
        type = lib.types.listOf (
          lib.types.enum [
            0
            1
            2
            3
            4
            7
          ]
        );
        default = [ ];
        description = ''
          PCRs to lock via systemd-pcrlock.
        '';
      };

      pcrlockDirectory = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/pcrlock.d";
        description = ''
          Directory to store the pcrlock files in.
        '';
      };

      pcrlockPolicy = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/systemd/pcrlock.json";
        description = ''
          Location to store the pcrlock policy in.
        '';
      };

      upstreamStaticMeasurements = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          Filenames of static pcrlock measurements to include from the systemd
          package.
        '';
      };

      staticMeasurements = lib.mkOption {
        default = { };
        description = ''
          Static systemd-pcrlock measurements.
        '';
        type = lib.types.attrsOf (
          lib.types.submodule (
            {
              name,
              config,
              options,
              ...
            }:
            {
              options = {
                source = lib.mkOption {
                  type = lib.types.path;
                  description = "Path of the source file.";
                };
                json = lib.mkOption {
                  default = null;
                  type = lib.types.nullOr json.type;
                  description = ''
                    systemd-pcrlock components in their literal form. This option is directly transformed to a JSON.
                  '';
                };
              };
              config = {
                source = lib.mkIf (config.json != null) (
                  lib.mkDerivedConfig options.json (json.generate "${name}.pcrlock")
                );
              };
            }
          )
        );
      };

      autoCryptenroll = {
        enable = lib.mkEnableOption "automatically enrolling the TPM2 policy into a LUKS volume";

        device = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = ''
            The device that is encrypted via LUKS2 to enroll the TPM2 policy into.

            With a plain device path, enrolment can only proceed when an
            existing TPM2 enrolment can unlock the volume, for example to
            upgrade from a static PCR binding to the full policy. Use
            {option}`volume` instead to also enrol volumes that were
            unlocked with a passphrase or key file.
          '';
        };

        volume = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = ''
            The name of an entry in {option}`boot.initrd.luks.devices` to
            enroll the TPM2 policy into.

            Unlike {option}`device`, this also wires up the volume so that
            its key is available for enrolment after any successful unlock,
            including by passphrase or key file. A volume that is not yet
            enrolled is then enrolled automatically on the first boot after
            it was unlocked, without storing any secret: possession of the
            unlocked volume is the credential.
          '';
        };

        autoReboot = lib.mkEnableOption "" // {
          description = ''
            Whether to automatically reboot after a volume was enrolled.

            Enrolment can shift the firmware PCR predictions, so the boot
            after it may need the fallback credential once before the policy
            settles. Enabling this absorbs that boot immediately rather than
            leaving it for the next manual reboot. Boots where the volume is
            already enrolled never reboot.
          '';
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.autoEnrollKeys.allowBrickingMyMachine -> cfg.autoEnrollKeys.includeMicrosoftKeys;
        message = ''
          You have set potentially dangerous Secure Boot enrollment settings. This might brick your machine.

            You have two options:
            1. Include the Microsoft keys via autoEnrollKeys.includeMicrosoftKeys
            2. Accept the risk via autoEnrollKeys.allowBrickingMyMachine
        '';
      }
      {
        assertion =
          autoCryptenrollCfg.enable
          -> ((autoCryptenrollCfg.device != null) != (autoCryptenrollCfg.volume != null));
        message = ''
          boot.lanzaboote.measuredBoot.autoCryptenroll requires exactly one of
          `device` (a plain device path, re-enrolment via an existing TPM2
          token only) or `volume` (a boot.initrd.luks.devices entry, also
          enables enrolment after a passphrase or key file unlock).
        '';
      }
      {
        assertion = cfg.measuredBoot.enable -> (configurationLimit > 0 && configurationLimit <= 8);
        message = ''
          If Measured Boot is enabled, you cannot store more than 8 generations on the ESP.

            This is a strict limit required and enforced by systemd-pcrlock.

            Set `boot.lanzaboote.configurationLimit = 8;` to reduce the number of generations you store.
        '';
      }
    ];

    boot.bootspec = {
      extensions."org.nix-community.lanzaboote" = {
        sort_key = config.boot.lanzaboote.sortKey;
      };
    };
    boot.loader.supportsInitrdSecrets = true;
    boot.loader.external = {
      enable = true;
      installHook = "${installHook}/bin/lzbt";
    };
    boot.lanzaboote.measuredBoot.upstreamStaticMeasurements =
      lib.optionals (pcr 0 || pcr 1 || pcr 2 || pcr 3 || pcr 4) [
        "500-separator.pcrlock.d/300-0x00000000.pcrlock"
      ]
      ++ lib.optionals (pcr 4) [
        "350-action-efi-application.pcrlock"
      ]
      ++ lib.optionals (pcr 7) [
        "400-secureboot-separator.pcrlock.d/300-0x00000000.pcrlock"
      ];

    environment.etc."sbctl/sbctl.conf" =
      lib.mkIf (cfg.autoGenerateKeys.enable || cfg.autoEnrollKeys.enable)
        {
          source = sbctlConfigFile;
        };

    # Write this to /etc so that manually calling systemd-pcrlock by the user
    # still works without them having to specify the directory.
    environment.etc."pcrlock" = lib.mkIf cfg.measuredBoot.enable {
      target = "pcrlock.d";
      source = staticMeasurements;
    };

    systemd.additionalUpstreamSystemUnits = lib.mkIf cfg.measuredBoot.enable [
      "systemd-pcrlock-make-policy.service"
      "systemd-pcrlock-firmware-code.service"
      "systemd-pcrlock-firmware-config.service"
      "systemd-pcrlock-secureboot-policy.service"
      "systemd-pcrlock-secureboot-authority.service"
    ];
    # The lock-* services scan the boot-time state of the system; they only
    # make sense at the start of a boot, while the event log still matches
    # the PCRs. Their unit files embed the systemd store path, so without
    # this every systemd upgrade would restart them during the switch, where
    # their event log validation can legitimately refuse and fail the whole
    # activation.
    systemd.services.systemd-pcrlock-firmware-code = lib.mkIf cfg.measuredBoot.enable {
      restartIfChanged = false;
    };
    systemd.services.systemd-pcrlock-firmware-config = lib.mkIf cfg.measuredBoot.enable {
      restartIfChanged = false;
    };
    # Since we might want to include PCR7 (the Secure Boot policy) we can only
    # create these measurements after we have booted in a Secure Boot system
    # for the first time. Thus, run this only if Secure Boot is already enabled
    # if we autoEnrollKeys.
    systemd.services.systemd-pcrlock-secureboot-policy = lib.mkMerge [
      (lib.mkIf (cfg.measuredBoot.enable && cfg.autoEnrollKeys.enable) {
        unitConfig.ConditionSecurity = "uefi-secureboot";
      })
      (lib.mkIf cfg.measuredBoot.enable { restartIfChanged = false; })
    ];
    systemd.services.systemd-pcrlock-secureboot-authority = lib.mkMerge [
      (lib.mkIf (cfg.measuredBoot.enable && cfg.autoEnrollKeys.enable) {
        unitConfig.ConditionSecurity = "uefi-secureboot";
      })
      (lib.mkIf cfg.measuredBoot.enable { restartIfChanged = false; })
    ];

    systemd.services.systemd-pcrlock-make-policy = lib.mkMerge [
      (lib.mkIf cfg.measuredBoot.enable {
        wantedBy = [ "sysinit.target" ];

        serviceConfig.ExecStart = [
          "" # unset previous value
          makePolicyCommand
        ];
      })

      # make-policy writes the boot loader credential to the ESP. Upstream
      # assumes the GPT auto-generator mounts the ESP early, but NixOS
      # disables that generator and uses fstab mounts instead. Ensure the
      # ESP is available.
      (lib.mkIf (cfg.measuredBoot.enable || config.systemd.pcrlock.enable) {
        after = [ "local-fs.target" ];

        # The install hook refreshes the policy during the switch, so
        # restarting this boot-time unit on activation is redundant.
        restartIfChanged = false;
      })

      # The upstream unit predicts only the single point in the boot where
      # the initrd unseals (--location=770), and covers PCRs that change
      # between that point and the main runtime. Updating the NV index
      # requires unsealing the recovery PIN under the old policy, and the
      # install hook does that at switch time, where such a prediction can
      # no longer match. Run the same firmware-PCR command as the install
      # hook so the two writers never rewrite each other's prediction.
      (lib.mkIf (config.systemd.pcrlock.enable && !cfg.measuredBoot.enable) {
        serviceConfig.ExecStart = [
          ""
          combinedMakePolicyCommand
        ];
      })
    ];
    systemd.targets.sysinit = lib.mkIf cfg.measuredBoot.enable {
      wants =
        lib.optionals (pcr 0 || pcr 2) [
          "systemd-pcrlock-firmware-code.service"
        ]
        ++ lib.optionals (pcr 1 || pcr 3) [
          "systemd-pcrlock-firmware-config.service"
        ]
        ++ lib.optionals (pcr 7) [
          "systemd-pcrlock-secureboot-policy.service"
          "systemd-pcrlock-secureboot-authority.service"
        ];
    };

    systemd.services.generate-sb-keys = lib.mkIf cfg.autoGenerateKeys.enable {
      wantedBy = [ "multi-user.target" ];

      unitConfig = {
        # Check to make sure keys directory is not present. Needs to check for
        # a subdirectory of pkiBundle as typically in impermanence-based configs
        # pkiBundle will be persisted, so it will always exist and is not
        # a true determination of whether keys have been generated previously.
        ConditionPathExists = "!${cfg.pkiBundle}/keys";
      };

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.sbctl}/bin/sbctl create-keys";
      };
    };

    # Generate the EFI Authenticated Variables from the keys using sbctl, place
    # them on the ESP, and re-sign all artifacts on the ESP with Lanzaboote.
    # The actual enrollment of the keys into the firmware is done on the next
    # boot via systemd-boot.
    systemd.services.prepare-sb-auto-enroll = lib.mkIf cfg.autoEnrollKeys.enable {
      wantedBy = [ "multi-user.target" ];
      after = [ "generate-sb-keys.service" ];

      unitConfig = {
        ConditionPathExists = [
          "!${espMountPoint}/loader/keys/auto/PK.auth"
          "!${espMountPoint}/loader/keys/auto/KEK.auth"
          "!${espMountPoint}/loader/keys/auto/db.auth"
        ];
        SuccessAction = lib.mkIf cfg.autoEnrollKeys.autoReboot "reboot";
      };

      serviceConfig = {
        Type = "oneshot";
        # SuccessAction doesn't trigger if the service is RemainAfterExit
        RemainAfterExit = lib.mkIf (!cfg.autoEnrollKeys.autoReboot) true;
        RuntimeDirectory = "prepare-sb-auto-enroll";
        WorkingDirectory = "/run/prepare-sb-auto-enroll";
      };

      script =
        let
          sbctlArgs = lib.concatStringsSep " " (
            [ "--export auth" ]
            ++ lib.optionals cfg.autoEnrollKeys.includeMicrosoftKeys [ "--microsoft" ]
            ++ lib.optionals cfg.autoEnrollKeys.includeChecksumsFromTPM [ "--tpm-eventlog" ]
            ++ lib.optionals cfg.autoEnrollKeys.allowBrickingMyMachine [
              "--yes-this-might-brick-my-machine"
            ]
          );
        in
        ''
          ${pkgs.sbctl}/bin/sbctl enroll-keys ${sbctlArgs}

          mkdir -p ${espMountPoint}/loader/keys/auto
          install {PK,KEK,db}.auth ${espMountPoint}/loader/keys/auto/

          # Re-sign all the artifacts on the ESP after the new keys have been
          # auto enrolled.
          ${installHook}/bin/lzbt
        '';
    };

    # Link the volume key into the kernel keyring on every successful
    # unlock, so the enrolment service can use it as the credential. The
    # service unlinks it again once it has run.
    boot.initrd.luks.devices = lib.mkIf autoCryptenrollCfg.enable (
      lib.optionalAttrs (autoCryptenrollCfg.volume != null) {
        ${autoCryptenrollCfg.volume}.crypttabExtraOpts = [
          "link-volume-key=@u::%user:${volumeKeyDescription}"
        ];
      }
    );

    systemd.services.auto-cryptenroll = lib.mkIf autoCryptenrollCfg.enable {
      description = "Enroll the TPM2 policy into the LUKS volume";

      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-pcrlock-make-policy.service" ];

      unitConfig.ConditionSecurity = lib.mkIf cfg.autoEnrollKeys.enable "uefi-secureboot";

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # The volume key in the root user keyring is only readable by a
        # possessor. The default private keyring mode gives the service a
        # session keyring with no link to the user keyring, so possession
        # never applies; the shared mode links it up.
        KeyringMode = "shared";
        ExecStart = lib.getExe autoCryptenrollScript;
      };
    };

    systemd.services.fwupd = lib.mkIf config.services.fwupd.enable {
      # Tell fwupd to load its efi files from /run
      environment.FWUPD_EFIAPPDIR = "/run/fwupd-efi";
    };

    systemd.services.fwupd-efi = lib.mkIf config.services.fwupd.enable {
      description = "Sign fwupd EFI app";
      # Exist with the lifetime of the fwupd service
      wantedBy = [ "fwupd.service" ];
      partOf = [ "fwupd.service" ];
      before = [ "fwupd.service" ];
      # Create runtime directory for signed efi app
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "fwupd-efi";
      };
      # Place the fwupd efi files in /run and sign them
      script = ''
        ln -sf ${config.services.fwupd.package.fwupd-efi}/libexec/fwupd/efi/fwupd*.efi /run/fwupd-efi/
        ${lib.getExe' pkgs.sbsigntool "sbsign"} --key '${cfg.privateKeyFile}' --cert '${cfg.publicKeyFile}' /run/fwupd-efi/fwupd*.efi
      '';
    };

    # systemd-measure signs the PCR 11 values for the boot phase strings
    # from enter-initrd onwards, so the signed policy can only ever be
    # satisfied when the phases are actually measured.
    systemd.tpm2.pcrphases.enable = lib.mkIf cfg.pcrSigning.enable (lib.mkDefault true);
    boot.initrd.systemd.tpm2.pcrphases.enable = lib.mkIf (
      cfg.pcrSigning.enable && config.boot.initrd.systemd.enable
    ) (lib.mkDefault true);

    # Copy PCR signature and public key from the initrd's /.extra/ (populated by
    # the stub's CPIO delivery) to /run/systemd/ where systemd-cryptenroll and
    # other tools expect them.  The 'C' type copies if the source exists and is
    # a no-op otherwise, so this is safe even when the stub doesn't embed pcrsig.
    boot.initrd.systemd.tmpfiles.settings."20-lanzaboote-stub" =
      lib.mkIf config.boot.initrd.systemd.enable
        {
          "/run/systemd/tpm2-pcr-signature.json".C = {
            argument = "/.extra/tpm2-pcr-signature.json";
            mode = "0444";
          };
          "/run/systemd/tpm2-pcr-public-key.pem".C = {
            argument = "/.extra/tpm2-pcr-public-key.pem";
            mode = "0444";
          };
        };

    systemd.services.fwupd-pcrlock-unlock-firmware-code =
      lib.mkIf
        (config.services.fwupd.enable && config.systemd.pcrlock.enable && cfg.fwupd.autoUnlockFirmwareCode)
        {
          description = "Relax pcrlock firmware-code policy for fwupd-staged capsule updates";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = [
              "${config.systemd.package}/lib/systemd/systemd-pcrlock unlock-firmware-code"
              combinedMakePolicyCommand
            ];
          };
          unitConfig = {
            ConditionPathExistsGlob = "/sys/firmware/efi/efivars/fwupd-*-0abba7dc-e516-4167-bbf5-4d9d1c739416";
            ConditionPathExists = [
              "/var/lib/pcrlock.d/250-firmware-code-early.pcrlock.d/generated.pcrlock"
              "/var/lib/pcrlock.d/550-firmware-code-late.pcrlock.d/generated.pcrlock"
            ];
          };
        };

    systemd.paths.fwupd-pcrlock-unlock-firmware-code =
      lib.mkIf
        (config.services.fwupd.enable && config.systemd.pcrlock.enable && cfg.fwupd.autoUnlockFirmwareCode)
        {
          description = "Watch for fwupd-staged capsule updates that require pcrlock firmware-code unlock";
          wantedBy = [ "multi-user.target" ];
          pathConfig = {
            PathExistsGlob = "/sys/firmware/efi/efivars/fwupd-*-0abba7dc-e516-4167-bbf5-4d9d1c739416";
            Unit = "fwupd-pcrlock-unlock-firmware-code.service";
          };
        };

    services.fwupd.uefiCapsuleSettings = lib.mkIf config.services.fwupd.enable {
      DisableShimForSecureBoot = true;
    };
  };
}
