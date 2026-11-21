{ config, lib, pkgs, ... }:

let
  cfg = config.services.hephaestus;

  extractPort = addr:
    let
      parts = lib.strings.splitString ":" addr;
    in
    lib.toInt (lib.last parts);

  clientFpFlags = lib.concatMap (fp: [ "--allow-client-fp" fp ]) cfg.allowClientFingerprints;

  execArgs =
    [
      "${lib.getExe cfg.package}"
      "--http-bind" cfg.httpListenAddress
      "--quic-bind" cfg.quicListenAddress
      "--data-dir" cfg.dataDir
      "--ltx-interval-secs" (toString cfg.ltxIntervalSecs)
    ]
    ++ lib.optionals (cfg.objectUri != null) [ "--object-uri" cfg.objectUri ]
    ++ lib.optionals (cfg.driveUrl != null) [ "--drive-url" cfg.driveUrl ]
    ++ lib.optionals (cfg.webhookUrl != null) [ "--webhook-url" cfg.webhookUrl ]
    ++ lib.optionals (cfg.jjRepo != null) [ "--jj-repo" cfg.jjRepo ]
    ++ lib.optionals (cfg.tlsKeyPath != null) [ "--tls-key-path" cfg.tlsKeyPath ]
    ++ lib.optionals cfg.devEphemeral [ "--dev-ephemeral" ]
    ++ clientFpFlags;
in
{
  options.services.hephaestus = {
    enable = lib.mkEnableOption "Hephaestus authoritative Jujutsu storage and IPv6 QUIC server";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.hephaestus-server;
      defaultText = lib.literalExpression "pkgs.hephaestus-server";
      description = "Hephaestus server package providing the `hephaestus-server` binary.";
    };

    httpListenAddress = lib.mkOption {
      type = lib.types.str;
      default = "[::1]:8081";
      example = "[fd00:db8::1]:8081";
      description = "Pure-IPv6 socket address for the HTTP/1.1 REST and streaming Git smart-HTTP bridge.";
    };

    quicListenAddress = lib.mkOption {
      type = lib.types.str;
      default = "[::1]:8443";
      example = "[fd00:db8::1]:8443";
      description = "Pure-IPv6 UDP socket address for the Ed25519 mTLS SPKI-pinned QUIC endpoint.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/hephaestus";
      description = "Directory holding SQLite WAL catalog/logs, persisted TLS key (if unset), and LocalFS objects.";
    };

    tlsKeyEncryptedFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional systemd-creds encrypted Ed25519 PKCS#8 PEM key loaded via LoadCredentialEncrypted=tls-ed25519.pem.";
    };

    tlsKeyPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional plaintext Ed25519 PKCS#8 PEM path passed to `--tls-key-path` when not using LoadCredentialEncrypted=.";
    };

    ltxIntervalSecs = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 300;
      description = "Interval in seconds between background Litestream LTX1 Zstd snapshot uploads (0 disables).";
    };

    objectUri = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "s3://hephaestus-artifacts/cas";
      description = "Optional `object_store` URI (`file://`, `s3://`, `gs://`, or `memory://`). Defaults to LocalFS under `dataDir/objects`.";
    };

    driveUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "";
      description = "Enable native-IPv6 Google Drive (`drive.file`) object backend. Use empty string `\"\"` for default Google Drive API v3 base URL.";
    };

    driveTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Optional secret file containing a short-lived Drive OAuth access token loaded via systemd LoadCredential=drive-access-token.";
    };

    webhookUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "http://[::1]:9090/v1/ci/push";
      description = "Optional IPv6 webhook endpoint notified once per unique bookmark push.";
    };

    jjRepo = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/hephaestus/repos";
      description = "Optional local Jujutsu repository root (single workspace or multi-repo directory) served over Git smart-HTTP and `/v1/jj/ops`.";
    };

    allowClientFingerprints = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ];
      description = "Authorized Ed25519 client SPKI SHA-256 fingerprints (64-char hex, verified in constant time). Required unless devEphemeral = true.";
    };

    devEphemeral = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Allow ephemeral local development without pre-configured client SPKI pins (never enable in production).";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open TCP (`httpListenAddress`) and UDP (`quicListenAddress`) ports in the host firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ (extractPort cfg.httpListenAddress) ];
      allowedUDPPorts = [ (extractPort cfg.quicListenAddress) ];
    };

    systemd.services.hephaestus = {
      description = "Hephaestus Authoritative Jujutsu Storage and IPv6 QUIC Server";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        StateDirectory = "hephaestus";
        StateDirectoryMode = "0750";
        ExecStart = lib.escapeShellArgs execArgs;
        Restart = "on-failure";
        RestartSec = "3s";
        LoadCredential = lib.mkIf (cfg.driveTokenFile != null) [
          "drive-access-token:${toString cfg.driveTokenFile}"
        ];
        LoadCredentialEncrypted = lib.mkIf (cfg.tlsKeyEncryptedFile != null) [
          "tls-ed25519.pem:${toString cfg.tlsKeyEncryptedFile}"
        ];

        # Hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = "";
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
      };
    };
  };
}
