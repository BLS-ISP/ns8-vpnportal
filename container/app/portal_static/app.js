/**
 * ns8-vpn End-User Self-Service Web Portal (Phase 2 + Phase 3)
 * Modular ES2022 Vanilla JS · Strict CSP safe · Zero innerHTML · Bilingual (DE / EN)
 */
(() => {
  "use strict";

  const STORAGE_LANG_KEY = "ns8_vpn_portal_lang";
  const CSRF_HEADER_NAME = "X-Requested-With";
  const CSRF_HEADER_VALUE = "NS8VPNPortal";
  const POLL_INTERVAL_MS = 25000;
  const DEVICE_NAME_REGEX = /^[\w\s.\-()'\u00C0-\u024F]{1,64}$/;
  const TOTP_CODE_REGEX = /^[0-9]{6}$/;
  const SAFE_QR_DATA_URI_REGEX = /^data:image\/(svg\+xml|png)(;charset=utf-8)?;base64,[A-Za-z0-9+/=\s]+$/i;

  const OFFICIAL_LINKS = {
    windows: {
      wireguard: "https://www.wireguard.com/install/",
      openvpn: "https://openvpn.net/client/",
    },
    macos: {
      wireguard: "https://apps.apple.com/app/wireguard/id1451685025",
      openvpn: "https://openvpn.net/client/",
    },
    ios: {
      wireguard: "https://apps.apple.com/app/wireguard/id1441195209",
      openvpn: "https://apps.apple.com/app/openvpn-connect-openvpn-app/id590379981",
    },
    android: {
      wireguard: "https://play.google.com/store/apps/details?id=com.wireguard.android",
      openvpn: "https://play.google.com/store/apps/details?id=net.openvpn.openvpn",
    },
    linux: {
      wireguard: "https://www.wireguard.com/install/",
      openvpn: "https://openvpn.net/cloud-docs/owner/connectors/connector-user-guides/openvpn-3-client-for-linux.html",
    },
  };

  /* ========================================================================
     1. Complete Bilingual Dictionary (DE & EN)
     ======================================================================== */

  const I18N = {
    de: {
      pageTitle: "Unternehmens-VPN · Self-Service-Portal",
      nav: {
        skipToContent: "Zum Hauptinhalt springen",
        langGroupLabel: "Sprache auswählen",
        refresh: "Verbindungsstatus aktualisieren",
        logout: "Abmelden",
      },
      brand: {
        title: "Unternehmens-VPN",
      },
      common: {
        loading: "Portal wird geladen…",
        retry: "Erneut prüfen",
        cancel: "Abbrechen",
        close: "Dialog schließen",
        done: "Fertig",
        copy: "Kopieren",
        copied: "Kopiert!",
      },
      disabled: {
        title: "Self-Service-Portal nicht verfügbar",
        description: "Das VPN-Self-Service-Portal ist derzeit durch die IT-Administration deaktiviert.",
        unreachable: "Der VPN-Dienst ist momentan nicht erreichbar. Bitte versuchen Sie es in wenigen Augenblicken erneut.",
      },
      login: {
        title: "Am VPN-Portal anmelden",
        subtitle: "Melden Sie sich mit Ihrem Unternehmens-Benutzerkonto (AD / LDAP) an, um Ihre VPN-Zugänge zu verwalten.",
        totpStepSubtitle: "Zwei-Faktor-Prüfung für Ihr Benutzerkonto erforderlich.",
        usernameLabel: "Benutzername",
        usernamePlaceholder: "z. B. m.mustermann",
        usernameHint: "Ihr Firmen-Benutzername im zentralen Verzeichnis",
        passwordLabel: "Passwort",
        showPassword: "Passwort im Klartext anzeigen",
        hidePassword: "Passwort verbergen",
        showShort: "Anzeigen",
        hideShort: "Verbergen",
        totpLabel: "6-stelliger Authenticator-Code",
        totpHint: "Öffnen Sie Ihre Authenticator-App und geben Sie den aktuellen 6-stelligen Code ein.",
        submitBtn: "Anmelden",
        submitSubmitting: "Anmeldung wird geprüft…",
        verifySubmitBtn: "Code bestätigen & anmelden",
        backBtn: "Zurück zur Kontowahl",
        securityNote: "Geschützte Verbindung · Authentifizierung gegen das zentrale Unternehmensverzeichnis",
      },
      totpGate: {
        policyBadge: "Pflichtrichtlinie · 2FA erforderlich",
        title: "Zwei-Faktor-Authentifizierung einrichten",
        description: "Ihre Organisation verlangt vor dem Erstellen oder Herunterladen von VPN-Profilen die Einrichtung eines zweiten Faktors (TOTP). Dieser Vorgang dauert nur eine Minute.",
        step1Title: "Authenticator-App auf dem Smartphone öffnen",
        step1Body: "Verwenden Sie z. B. Microsoft Authenticator, Google Authenticator, 2FAS, Ente Auth, FreeOTP oder Apple Passwörter.",
        step2Title: "QR-Code scannen oder Schlüssel manuell übernehmen",
        generatingQr: "Schlüssel wird erzeugt…",
        qrAlt: "QR-Code zur Einrichtung der Zwei-Faktor-Authentifizierung",
        manualHint: "Kein Kamera-Scan möglich? Tragen Sie diesen Base32-Schlüssel manuell in Ihrer App ein:",
        regenerateBtn: "Neuen Schlüssel anfordern",
        step3Title: "6-stelligen Bestätigungscode eingeben",
        verifyBtn: "2FA aktivieren & Portal freischalten",
        verifyingBtn: "Code wird geprüft…",
        unlockedToast: "Zwei-Faktor-Authentifizierung erfolgreich aktiviert.",
      },
      dashboard: {
        greetingNamed: "Guten Tag, {name}",
        greetingDefault: "Willkommen im VPN-Portal",
        subtitle: "Verwalten Sie Ihre persönlichen VPN-Geräteprofile für den sicheren Zugriff auf das Unternehmensnetzwerk.",
        serverLabel: "VPN-Server",
        routingLabel: "Modus",
        routingSplit: "Split-Tunnel (Firmennetz)",
        routingFull: "Full-Tunnel (Gesamtverkehr)",
        twoFactorLabel: "2FA-Schutz",
        twoFactorActive: "Aktiv",
        twoFactorOptionalOff: "Nicht eingerichtet",
        refreshedToast: "Gerätestatus wurde aktualisiert.",
      },
      wg: {
        recommendedBadge: "Empfohlen",
        protocolNote: "UDP · Höchste Geschwindigkeit & nahtloser WLAN/Mobilfunk-Wechsel",
        title: "Standard-Profil – WireGuard",
        subtitle: "Jedes Endgerät erhält einen eigenen kryptografischen Schlüssel. Wählen Sie Ihr Gerät aus, um sofort einen QR-Code oder eine Konfigurationsdatei zu erhalten.",
        quotaLabel: "Gerätekontingent",
        quotaCountText: "{used} / {max} belegt",
        newDeviceLabel: "Neues Gerät einrichten",
        quickChipsLabel: "Schnellauswahl für Gerätenamen",
        chips: ["Arbeits-Laptop", "iPhone", "Android-Smartphone", "iPad", "Home-PC"],
        devicePlaceholder: "Gerätename eingeben (z. B. Arbeits-Laptop)",
        createBtn: "Gerät hinzufügen",
        creatingBtn: "Profil wird erstellt…",
        nameRulesHint: "Erlaubt sind Buchstaben, Zahlen, Leerzeichen sowie . - _ ( ) (max. 64 Zeichen).",
        quotaReachedHint: "Sie haben Ihr maximales Kontingent von {max} Geräten erreicht. Entfernen Sie unten ein nicht mehr genutztes Gerät, um ein neues anzulegen.",
        devicesHeading: "Ihre registrierten Geräte",
        onlineSummary: "{online} von {total} aktuell verbunden",
        emptyTitle: "Noch kein Gerät eingerichtet",
        emptyBody: "Wählen Sie oben einen Gerätenamen wie „Arbeits-Laptop“ oder „iPhone“ aus und klicken Sie auf „Gerät hinzufügen“.",
        statusOnline: "Verbunden (Online)",
        statusOffline: "Bereit (Offline)",
        statusSuspended: "Durch IT gesperrt",
        createdOn: "Erstellt am {date}",
        tunnelIpLabel: "Tunnel-IP",
        trafficLabel: "Datenvolumen",
        handshakeLabel: "Letzter Handshake",
        neverConnected: "Noch nie verbunden",
        justNow: "Gerade eben",
        minutesAgo: "vor {n} Min.",
        hoursAgo: "vor {n} Std.",
        profileQrBtn: "Profil / QR-Code",
        removeDeviceBtn: "Gerät entfernen",
        deviceCreatedToast: "WireGuard-Profil für „{name}“ wurde erstellt.",
        deviceRemovedToast: "Gerät „{name}“ wurde entfernt.",
      },
      ovpn: {
        fallbackBadge: "TCP / Gast-WLAN Fallback",
        title: "Kompatibilitäts- & Hotel-Profil – OpenVPN",
        description: "Ideal für Hotels, Kliniken, Messen und Gast-WLANs, in denen UDP blockiert ist. Verbindet per Passwortabfrage.",
        bulletQuota: "Zählt nicht gegen Ihr WireGuard-Gerätekontingent und kann auf mehreren Geräten hinterlegt werden.",
        bulletAuth: "Fragt beim Verbindungsaufbau Ihren AD/LDAP-Benutzernamen und Ihr aktuelles Passwort ab.",
        totpRequiredTitle: "Wichtig beim Verbinden: Passwort + 6-stelliger 2FA-Code",
        totpRequiredBody: "Für OpenVPN ist die Zwei-Faktor-Prüfung aktiviert. Hängen Sie beim Verbinden Ihren aktuellen 6-stelligen Authenticator-Code direkt und ohne Leerzeichen an Ihr AD-Passwort an:",
        passwordFieldLabel: "Eingabe im Passwortfeld:",
        passwordFieldExample: "IhrPasswort123456",
        enrollFirstBtn: "Jetzt zuerst 2FA einrichten",
        downloadBtn: ".ovpn-Profil herunterladen",
        downloadingBtn: "Profil wird geladen…",
        downloadedToast: "OpenVPN-Profil ({filename}) wurde heruntergeladen.",
      },
      security: {
        title: "Zwei-Faktor-Authentifizierung (2FA)",
        badgeActive: "2FA Aktiv",
        badgeInactive: "Optional · Nicht aktiv",
        badgeRequired: "Pflicht · 2FA Aktiv",
        descOptionalOff: "Schützen Sie Ihren VPN-Portal-Zugang zusätzlich mit einem zeitbasierten 6-stelligen Einmalcode (TOTP) auf Ihrem Smartphone.",
        descOptionalOn: "Ihr Konto ist durch Zwei-Faktor-Authentifizierung geschützt. Bei jeder Anmeldung im Portal wird ein 6-stelliger Bestätigungscode abgefragt.",
        descRequiredOn: "Ihr Konto erfüllt die Sicherheitsrichtlinie für Zwei-Faktor-Authentifizierung.",
        requiredPolicyNote: "2FA ist durch Ihre Unternehmensrichtlinie dauerhaft vorgeschrieben. Bei Smartphone-Verlust kann Ihr IT-Helpdesk den zweiten Faktor zurücksetzen.",
        enableBtn: "2FA jetzt aktivieren",
        disableBtn: "2FA deaktivieren",
        disabledToast: "Zwei-Faktor-Authentifizierung wurde deaktiviert.",
      },
      wgModal: {
        titleWithDevice: "WireGuard-Profil: {name}",
        confidentialNotice: "Vertrauliches Zugangsprofil: Geben Sie diesen QR-Code oder die .conf-Datei nicht an Dritte weiter.",
        qrHeading: "Smartphone & Tablet (QR-Code)",
        qrAlt: "WireGuard-Konfigurations-QR-Code",
        qrHint: "In der WireGuard-App auf „+“ tippen und „Aus QR-Code erstellen“ wählen.",
        fileHeading: "Computer (.conf-Konfigurationsdatei)",
        fileHint: "Laden Sie die Konfigurationsdatei herunter und importieren Sie sie mit einem Klick in das offizielle WireGuard-Programm.",
        downloadBtn: ".conf-Datei herunterladen",
        downloadedToast: "Konfigurationsdatei {filename} heruntergeladen.",
        previewSummary: "Konfigurationstext einblenden / kopieren",
      },
      deleteModal: {
        title: "Gerät entfernen",
        body: "Möchten Sie dieses Gerät wirklich entfernen? Eine bestehende VPN-Verbindung dieses Geräts wird sofort getrennt und das Profil dauerhaft ungültig gemacht.",
        confirmBtn: "Gerät entfernen",
        deletingBtn: "Wird entfernt…",
      },
      totpEnableModal: {
        title: "Zwei-Faktor-Authentifizierung aktivieren",
        instructions: "Scannen Sie den QR-Code mit Ihrer Authenticator-App (z. B. Microsoft/Google Authenticator, 2FAS) und bestätigen Sie anschließend den 6-stelligen Code.",
        secretLabel: "Manueller Base32-Schlüssel",
        confirmBtn: "Code prüfen & aktivieren",
      },
      totpDisableModal: {
        title: "2FA deaktivieren",
        description: "Zur Sicherheitsbestätigung geben Sie bitte Ihr aktuelles Unternehmens-Passwort sowie einen gültigen 6-stelligen Authenticator-Code ein.",
        confirmBtn: "2FA deaktivieren",
        disablingBtn: "Wird deaktiviert…",
      },
      guides: {
        title: "Schritt-für-Schritt-Einrichtung & Offizielle Apps",
        subtitle: "Wählen Sie Ihr Betriebssystem für die passende Kurzanleitung und die offiziellen App-Links.",
        osTablistLabel: "Betriebssystem auswählen",
        wgBoxTitle: "Standard: WireGuard einrichten",
        ovpnBoxTitle: "Hotel / Gast-WLAN: OpenVPN Connect",
        downloadWgBtn: "WireGuard herunterladen",
        downloadOvpnBtn: "OpenVPN Connect laden",
        ovpnTotpReminder: "Hinweis: Im Passwortfeld Ihr AD-Passwort direkt gefolgt vom 6-stelligen 2FA-Code eingeben.",
        os: {
          windows: {
            wgSteps: [
              "Installieren Sie das offizielle WireGuard-Programm für Windows.",
              "Erstellen Sie oben ein Gerät (z. B. „Arbeits-Laptop“) und laden Sie die .conf-Datei herunter.",
              "Öffnen Sie WireGuard und klicken Sie unten links auf „Tunnel aus Datei importieren…“.",
              "Klicken Sie auf „Aktivieren“ – bei grünem Haken steht die sichere Firmenverbindung.",
            ],
            ovpnSteps: [
              "Installieren Sie den offiziellen Client „OpenVPN Connect“ für Windows.",
              "Laden Sie oben unter „Kompatibilitäts- & Hotel-Profil“ Ihre .ovpn-Datei herunter.",
              "Öffnen Sie OpenVPN Connect -> „Upload File“ und wählen Sie die .ovpn-Datei aus.",
              "Verbinden Sie sich mit Ihrem Firmen-Benutzernamen und Passwort.",
            ],
          },
          macos: {
            wgSteps: [
              "Installieren Sie die offizielle WireGuard-App aus dem Mac App Store.",
              "Laden Sie oben für Ihren Mac die persönliche .conf-Konfigurationsdatei herunter.",
              "Klicken Sie in WireGuard auf „Tunnel aus Datei importieren“ und wählen Sie die .conf-Datei.",
              "Erlauben Sie die VPN-Konfiguration in macOS und klicken Sie auf „Aktivieren“.",
            ],
            ovpnSteps: [
              "Installieren Sie „OpenVPN Connect v3“ für macOS (Apple Silicon / Intel).",
              "Laden Sie oben Ihre .ovpn-Profildatei herunter.",
              "Doppelklicken Sie die .ovpn-Datei zum Importieren in OpenVPN Connect.",
              "Schalten Sie den Tunnel ein und melden Sie sich mit Ihrem Firmenkonto an.",
            ],
          },
          ios: {
            wgSteps: [
              "Installieren Sie die kostenlose App „WireGuard“ aus dem Apple App Store.",
              "Erstellen Sie oben ein Gerät (z. B. „iPhone“ oder „iPad“), sodass der QR-Code erscheint.",
              "Tippen Sie in der WireGuard-App oben rechts auf „+“ -> „Aus QR-Code erstellen“.",
              "Vergeben Sie einen Namen (z. B. „Firmen-VPN“), erlauben Sie das VPN-Profil und schalten Sie den Regler ein.",
            ],
            ovpnSteps: [
              "Installieren Sie „OpenVPN Connect“ aus dem Apple App Store.",
              "Tippen Sie oben auf „.ovpn-Profil herunterladen“ und teilen/öffnen Sie die Datei in OpenVPN Connect.",
              "Tippen Sie auf „Add“, tragen Sie Ihren Benutzernamen ein und erlauben Sie die VPN-Konfiguration.",
              "Aktivieren Sie den Schalter und geben Sie Ihr Passwort ein.",
            ],
          },
          android: {
            wgSteps: [
              "Installieren Sie die offizielle App „WireGuard“ aus dem Google Play Store.",
              "Erstellen Sie oben ein Gerät (z. B. „Android-Smartphone“), um den QR-Code anzuzeigen.",
              "Tippen Sie in der WireGuard-App unten rechts auf das blaue „+“ -> „Aus QR-Code scannen“.",
              "Benennen Sie den Tunnel (z. B. „Firma“) und aktivieren Sie den Schalter neben dem Profil.",
            ],
            ovpnSteps: [
              "Installieren Sie „OpenVPN Connect“ aus dem Google Play Store.",
              "Laden Sie oben Ihre .ovpn-Datei auf das Smartphone herunter.",
              "Wählen Sie in OpenVPN Connect „Upload File“ -> „Browse“ und importieren Sie die .ovpn-Datei.",
              "Verbinden Sie sich mit Ihrem Firmen-Benutzernamen und Passwort.",
            ],
          },
          linux: {
            wgSteps: [
              "Installieren Sie WireGuard bzw. das NetworkManager-Plugin über Ihre Paketverwaltung.",
              "Laden Sie oben Ihre .conf-Datei herunter (z. B. nach ~/Downloads/firma.conf).",
              "Importieren Sie das Profil in die Netzwerkeinstellungen per nmcli oder starten Sie es per wg-quick.",
              "Aktivieren Sie die VPN-Verbindung bequem über das Systemmenü oben rechts.",
            ],
            wgCli: "nmcli connection import type wireguard file ~/Downloads/vpn.conf",
            ovpnSteps: [
              "Installieren Sie network-manager-openvpn-gnome oder den offiziellen openvpn3-Linux-Client.",
              "Laden Sie oben Ihre .ovpn-Datei herunter.",
              "Importieren Sie die Datei über Systemeinstellungen -> Netzwerk -> VPN -> „Aus Datei importieren…“.",
              "Verbinden Sie sich mit Ihrem AD/LDAP-Benutzernamen und Passwort.",
            ],
          },
        },
      },
      errors: {
        usernameAndPasswordRequired: "Bitte geben Sie Benutzernamen und Passwort ein.",
        invalidTotpFormat: "Bitte geben Sie einen gültigen 6-stelligen Zahlencode ein.",
        passwordRequired: "Bitte geben Sie Ihr aktuelles Passwort ein.",
        invalidCredentials: "Benutzername oder Passwort ist ungültig.",
        invalidTotpCode: "Der 6-stellige Authenticator-Code ist ungültig oder abgelaufen. Bitte prüfen Sie die Uhrzeit Ihres Smartphones und geben Sie den aktuellen Code ein.",
        forbiddenAccount: "Ihr Konto ist für den VPN-Zugang nicht freigeschaltet oder im Verzeichnis deaktiviert.",
        rateLimited: "Zu viele Anmeldeversuche in kurzer Zeit. Bitte warten Sie einige Minuten und versuchen Sie es erneut.",
        sessionExpired: "Ihre Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.",
        totpEnrollmentRequired: "Bitte schließen Sie zuerst die Einrichtung der Zwei-Faktor-Authentifizierung ab.",
        invalidDeviceName: "Bitte geben Sie einen gültigen Gerätenamen ein (1–64 Zeichen; Buchstaben, Zahlen, Leerzeichen, . - _ ( )).",
        quotaExceeded: "Maximale Geräteanzahl erreicht. Bitte entfernen Sie zuerst ein bestehendes Gerät.",
        ipPoolExhausted: "Der VPN-Adresspool ist aktuell ausgeschöpft. Bitte wenden Sie sich an die IT-Administration.",
        notFound: "Das angeforderte Element wurde nicht gefunden.",
        networkError: "Netzwerkfehler bei der Verbindung zum VPN-Portal. Bitte prüfen Sie Ihre Internetverbindung.",
        serverError: "Der Server konnte die Anfrage vorübergehend nicht verarbeiten. Bitte versuchen Sie es erneut.",
        invalidQrPayload: "Der empfangene QR-Code konnte aus Sicherheitsgründen nicht dargestellt werden.",
      },
    },

    en: {
      pageTitle: "Corporate VPN · Self-Service Portal",
      nav: {
        skipToContent: "Skip to main content",
        langGroupLabel: "Select language",
        refresh: "Refresh connection status",
        logout: "Sign out",
      },
      brand: {
        title: "Corporate VPN",
      },
      common: {
        loading: "Loading portal…",
        retry: "Check again",
        cancel: "Cancel",
        close: "Close dialog",
        done: "Done",
        copy: "Copy",
        copied: "Copied!",
      },
      disabled: {
        title: "Self-Service Portal Unavailable",
        description: "The VPN self-service portal is currently disabled by your IT administrator.",
        unreachable: "The VPN service is temporarily unreachable. Please try again in a few moments.",
      },
      login: {
        title: "Sign in to VPN Portal",
        subtitle: "Sign in with your corporate directory account (AD / LDAP) to manage your VPN devices.",
        totpStepSubtitle: "Two-factor verification is required for your account.",
        usernameLabel: "Username",
        usernamePlaceholder: "e.g. j.doe",
        usernameHint: "Your corporate directory username",
        passwordLabel: "Password",
        showPassword: "Show password as plain text",
        hidePassword: "Hide password",
        showShort: "Show",
        hideShort: "Hide",
        totpLabel: "6-digit Authenticator code",
        totpHint: "Open your Authenticator app and enter the current 6-digit verification code.",
        submitBtn: "Sign in",
        submitSubmitting: "Verifying…",
        verifySubmitBtn: "Verify code & sign in",
        backBtn: "Back to account sign-in",
        securityNote: "Encrypted session · Authenticated against your central corporate directory",
      },
      totpGate: {
        policyBadge: "Security Policy · 2FA Required",
        title: "Set up Two-Factor Authentication",
        description: "Your organization requires setting up a second factor (TOTP) before creating or downloading VPN profiles. This only takes a minute.",
        step1Title: "Open an Authenticator app on your phone",
        step1Body: "Use Microsoft Authenticator, Google Authenticator, 2FAS, Ente Auth, FreeOTP, or Apple Passwords.",
        step2Title: "Scan the QR code or enter the key manually",
        generatingQr: "Generating secret key…",
        qrAlt: "QR code for Two-Factor Authentication setup",
        manualHint: "Cannot scan with a camera? Enter this Base32 secret manually in your app:",
        regenerateBtn: "Request a new key",
        step3Title: "Enter the 6-digit verification code",
        verifyBtn: "Enable 2FA & unlock portal",
        verifyingBtn: "Verifying code…",
        unlockedToast: "Two-factor authentication has been enabled.",
      },
      dashboard: {
        greetingNamed: "Welcome, {name}",
        greetingDefault: "Welcome to the VPN Portal",
        subtitle: "Manage your personal VPN device profiles for secure access to the corporate network.",
        serverLabel: "VPN Server",
        routingLabel: "Routing",
        routingSplit: "Split Tunnel (Corporate LAN)",
        routingFull: "Full Tunnel (All Traffic)",
        twoFactorLabel: "2FA Protection",
        twoFactorActive: "Enabled",
        twoFactorOptionalOff: "Not enabled",
        refreshedToast: "Device status updated.",
      },
      wg: {
        recommendedBadge: "Recommended",
        protocolNote: "UDP · Highest performance & seamless Wi-Fi / cellular roaming",
        title: "Standard Profile – WireGuard",
        subtitle: "Each device receives its own cryptographic keypair. Pick your device below to immediately get a QR code or configuration file.",
        quotaLabel: "Device Quota",
        quotaCountText: "{used} / {max} in use",
        newDeviceLabel: "Add a new device",
        quickChipsLabel: "Quick select device names",
        chips: ["Work Laptop", "iPhone", "Android Smartphone", "iPad", "Home PC"],
        devicePlaceholder: "Enter device name (e.g. Work Laptop)",
        createBtn: "Add device",
        creatingBtn: "Creating profile…",
        nameRulesHint: "Allowed: letters, numbers, spaces, and . - _ ( ) (up to 64 characters).",
        quotaReachedHint: "You have reached your maximum limit of {max} devices. Remove an unused device below to register a new one.",
        devicesHeading: "Your registered devices",
        onlineSummary: "{online} of {total} currently connected",
        emptyTitle: "No devices registered yet",
        emptyBody: "Select a device name above such as “Work Laptop” or “iPhone” and click “Add device”.",
        statusOnline: "Connected (Online)",
        statusOffline: "Ready (Offline)",
        statusSuspended: "Suspended by IT",
        createdOn: "Added {date}",
        tunnelIpLabel: "Tunnel IP",
        trafficLabel: "Traffic",
        handshakeLabel: "Last Handshake",
        neverConnected: "Never connected",
        justNow: "Just now",
        minutesAgo: "{n}m ago",
        hoursAgo: "{n}h ago",
        profileQrBtn: "Profile / QR Code",
        removeDeviceBtn: "Remove device",
        deviceCreatedToast: "WireGuard profile for “{name}” created.",
        deviceRemovedToast: "Device “{name}” removed.",
      },
      ovpn: {
        fallbackBadge: "TCP / Guest Wi-Fi Fallback",
        title: "Compatibility & Hotel Profile – OpenVPN",
        description: "Ideal for hotels, hospitals, trade fairs, and guest Wi-Fi networks where UDP is blocked. Connects via password prompt.",
        bulletQuota: "Does not count toward your WireGuard device limit and can be imported on multiple devices.",
        bulletAuth: "Prompts for your corporate AD/LDAP username and current password each time you connect.",
        totpRequiredTitle: "Important on connect: Password + 6-digit 2FA code",
        totpRequiredBody: "Two-factor verification is enabled for OpenVPN. When connecting, append your current 6-digit Authenticator code directly to the end of your AD password with no space:",
        passwordFieldLabel: "Enter in password field:",
        passwordFieldExample: "YourPassword123456",
        enrollFirstBtn: "Set up 2FA first",
        downloadBtn: "Download .ovpn profile",
        downloadingBtn: "Preparing profile…",
        downloadedToast: "OpenVPN profile ({filename}) downloaded.",
      },
      security: {
        title: "Two-Factor Authentication (2FA)",
        badgeActive: "2FA Enabled",
        badgeInactive: "Optional · Not enabled",
        badgeRequired: "Required · 2FA Enabled",
        descOptionalOff: "Protect your VPN portal sign-in with an additional time-based 6-digit one-time code (TOTP) on your smartphone.",
        descOptionalOn: "Your account is protected with two-factor authentication. Signing in requires a 6-digit verification code.",
        descRequiredOn: "Your account complies with your organization's mandatory two-factor security policy.",
        requiredPolicyNote: "2FA is permanently required by corporate security policy. If you lose your phone, contact your IT Helpdesk to reset 2FA.",
        enableBtn: "Enable 2FA now",
        disableBtn: "Disable 2FA",
        disabledToast: "Two-factor authentication has been disabled.",
      },
      wgModal: {
        titleWithDevice: "WireGuard Profile: {name}",
        confidentialNotice: "Confidential access profile: Never share this QR code or .conf file with anyone else.",
        qrHeading: "Smartphone & Tablet (QR Code)",
        qrAlt: "WireGuard configuration QR code",
        qrHint: "Open the WireGuard app, tap “+”, and choose “Create from QR code”.",
        fileHeading: "Computer (.conf Configuration File)",
        fileHint: "Download the configuration file and import it into the official WireGuard desktop app in one click.",
        downloadBtn: "Download .conf file",
        downloadedToast: "Configuration file {filename} downloaded.",
        previewSummary: "Show / copy configuration text",
      },
      deleteModal: {
        title: "Remove device",
        body: "Are you sure you want to remove this device? Any active VPN tunnel from this device will be disconnected immediately and its profile permanently revoked.",
        confirmBtn: "Remove device",
        deletingBtn: "Removing…",
      },
      totpEnableModal: {
        title: "Enable Two-Factor Authentication",
        instructions: "Scan the QR code using your Authenticator app (e.g. Microsoft/Google Authenticator, 2FAS) and enter the 6-digit verification code.",
        secretLabel: "Manual Base32 secret",
        confirmBtn: "Verify & enable",
      },
      totpDisableModal: {
        title: "Disable 2FA",
        description: "For security verification, enter your current corporate password along with a valid 6-digit Authenticator code.",
        confirmBtn: "Disable 2FA",
        disablingBtn: "Disabling…",
      },
      guides: {
        title: "Step-by-Step Setup Guides & Official Apps",
        subtitle: "Choose your operating system for concise setup instructions and official client download links.",
        osTablistLabel: "Select operating system",
        wgBoxTitle: "Standard: Set up WireGuard",
        ovpnBoxTitle: "Hotel / Guest Wi-Fi: OpenVPN Connect",
        downloadWgBtn: "Download WireGuard",
        downloadOvpnBtn: "Get OpenVPN Connect",
        ovpnTotpReminder: "Note: In the password prompt, enter your AD password immediately followed by your 6-digit 2FA code.",
        os: {
          windows: {
            wgSteps: [
              "Install the official WireGuard application for Windows.",
              "Add a device above (e.g. “Work Laptop”) and download the .conf file.",
              "Open WireGuard and click “Import tunnel(s) from file…” in the bottom left.",
              "Click “Activate” — once the status turns green, you are connected to the company network.",
            ],
            ovpnSteps: [
              "Install the official “OpenVPN Connect” client for Windows.",
              "Download your .ovpn file from the Compatibility & Hotel Profile card above.",
              "Open OpenVPN Connect -> “Upload File” and select your .ovpn profile.",
              "Connect using your corporate username and password.",
            ],
          },
          macos: {
            wgSteps: [
              "Install the official WireGuard app from the Mac App Store.",
              "Download your Mac's personal .conf configuration file above.",
              "In WireGuard, click “Import Tunnel(s) from File” and choose the .conf file.",
              "Allow the macOS VPN configuration prompt and click “Activate”.",
            ],
            ovpnSteps: [
              "Install “OpenVPN Connect v3” for macOS (Apple Silicon / Intel).",
              "Download your .ovpn profile file above.",
              "Double-click the downloaded .ovpn file to import it into OpenVPN Connect.",
              "Toggle the profile on and enter your corporate username and password.",
            ],
          },
          ios: {
            wgSteps: [
              "Install the free “WireGuard” app from the Apple App Store.",
              "Create a device above (e.g. “iPhone” or “iPad”) to display the QR code.",
              "In the WireGuard app, tap “+” in the top right -> “Create from QR code”.",
              "Name the tunnel (e.g. “Company VPN”), allow the VPN profile, and toggle the switch on.",
            ],
            ovpnSteps: [
              "Install “OpenVPN Connect” from the Apple App Store.",
              "Tap “Download .ovpn profile” above and share/open the file in OpenVPN Connect.",
              "Tap “Add”, enter your corporate username, and approve the iOS VPN permission.",
              "Toggle the connection switch and enter your password.",
            ],
          },
          android: {
            wgSteps: [
              "Install the official “WireGuard” app from the Google Play Store.",
              "Create a device above (e.g. “Android Smartphone”) to view the QR code.",
              "In the WireGuard app, tap the blue “+” button -> “Scan from QR code”.",
              "Enter a tunnel name (e.g. “Work”) and flip the switch next to the profile.",
            ],
            ovpnSteps: [
              "Install “OpenVPN Connect” from the Google Play Store.",
              "Download your .ovpn file onto your phone above.",
              "Open OpenVPN Connect -> “Upload File” -> “Browse” and select the .ovpn file.",
              "Connect with your corporate username and password.",
            ],
          },
          linux: {
            wgSteps: [
              "Install WireGuard and the NetworkManager WireGuard plugin via your package manager.",
              "Download your .conf file above (e.g. to ~/Downloads/vpn.conf).",
              "Import the profile into NetworkManager via nmcli or start it via wg-quick.",
              "Toggle the VPN connection conveniently from your desktop system menu.",
            ],
            wgCli: "nmcli connection import type wireguard file ~/Downloads/vpn.conf",
            ovpnSteps: [
              "Install network-manager-openvpn-gnome or the official openvpn3 Linux client.",
              "Download your .ovpn file above.",
              "Import it via System Settings -> Network -> VPN -> “Import from file…”.",
              "Connect using your corporate AD/LDAP username and password.",
            ],
          },
        },
      },
      errors: {
        usernameAndPasswordRequired: "Please enter both your username and password.",
        invalidTotpFormat: "Please enter a valid 6-digit numeric code.",
        passwordRequired: "Please enter your current password.",
        invalidCredentials: "Invalid username or password.",
        invalidTotpCode: "The 6-digit Authenticator code is invalid or expired. Check your phone's clock and enter the current code.",
        forbiddenAccount: "Your account is not authorized for VPN access or is disabled in the directory.",
        rateLimited: "Too many sign-in attempts. Please wait a few minutes before trying again.",
        sessionExpired: "Your session has expired. Please sign in again.",
        totpEnrollmentRequired: "Please finish setting up two-factor authentication first.",
        invalidDeviceName: "Please enter a valid device name (1–64 chars; letters, numbers, spaces, . - _ ( )).",
        quotaExceeded: "Maximum number of devices reached. Please remove an existing device first.",
        ipPoolExhausted: "No free VPN addresses are currently available. Please contact IT Support.",
        notFound: "The requested item could not be found.",
        networkError: "Network error communicating with the VPN portal. Please check your connection.",
        serverError: "The server could not process the request right now. Please try again.",
        invalidQrPayload: "The received QR code could not be displayed for security reasons.",
      },
    },
  };

  /* ========================================================================
     2. Application State
     ======================================================================== */

  const state = {
    lang: detectInitialLanguage(),
    activeView: "loading", // "loading" | "disabled" | "login" | "totp-mandatory" | "dashboard"
    disabledReasonKey: "disabled.description",
    portalInfo: null,
    me: null,
    loginStep: "credentials", // "credentials" | "totp"
    pendingLoginUsername: "",
    pendingLoginPassword: "",
    mandatoryTotpSecret: "",
    mandatoryTotpLoaded: false,
    modalTotpSecret: "",
    selectedOs: detectClientOs(),
    activeModalId: null,
    lastFocusedElement: null,
    wgModalContext: null, // { deviceName, assignedIp, filename, configText, qrSvgDataUri }
    deleteTargetDevice: null, // { id, device_name, assigned_ip }
    pollTimerId: null,
  };

  /* ========================================================================
     3. Safe DOM & Formatting Utilities (Zero innerHTML)
     ======================================================================== */

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, val] of Object.entries(props)) {
      if (val === undefined || val === null) continue;
      if (key === "className") {
        node.className = val;
      } else if (key === "text") {
        node.textContent = String(val);
      } else if (key === "dataset" && typeof val === "object") {
        for (const [dk, dv] of Object.entries(val)) {
          node.dataset[dk] = String(dv);
        }
      } else if (key.startsWith("on") && typeof val === "function") {
        node.addEventListener(key.slice(2).toLowerCase(), val);
      } else if (typeof val === "boolean") {
        if (val) node.setAttribute(key, "");
      } else {
        node.setAttribute(key, String(val));
      }
    }
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      if (typeof child === "string" || typeof child === "number") {
        node.appendChild(document.createTextNode(String(child)));
      } else {
        node.appendChild(child);
      }
    }
    return node;
  }

  function svgEl(tag, attrs = {}, children = []) {
    const ns = "http://www.w3.org/2000/svg";
    const node = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    for (const child of children) {
      node.appendChild(child);
    }
    return node;
  }

  function createIcon(kind, size = 18) {
    const base = {
      viewBox: "0 0 24 24",
      width: size,
      height: size,
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "1.8",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
    };

    switch (kind) {
      case "phone":
        return svgEl("svg", base, [
          svgEl("rect", { x: 6, y: 2, width: 12, height: 20, rx: 2 }),
          svgEl("line", { x1: 12, y1: 18, x2: 12.01, y2: 18 }),
        ]);
      case "tablet":
        return svgEl("svg", base, [
          svgEl("rect", { x: 4, y: 2, width: 16, height: 20, rx: 2 }),
          svgEl("line", { x1: 12, y1: 18, x2: 12.01, y2: 18 }),
        ]);
      case "desktop":
        return svgEl("svg", base, [
          svgEl("rect", { x: 2, y: 3, width: 20, height: 14, rx: 2 }),
          svgEl("line", { x1: 8, y1: 21, x2: 16, y2: 21 }),
          svgEl("line", { x1: 12, y1: 17, x2: 12, y2: 21 }),
        ]);
      case "qr":
        return svgEl("svg", base, [
          svgEl("rect", { x: 3, y: 3, width: 7, height: 7 }),
          svgEl("rect", { x: 14, y: 3, width: 7, height: 7 }),
          svgEl("rect", { x: 3, y: 14, width: 7, height: 7 }),
          svgEl("path", { d: "M14 14h3v3h-3zM18 18h3v3h-3zM18 14h3M14 18v3" }),
        ]);
      case "trash":
        return svgEl("svg", base, [
          svgEl("polyline", { points: "3 6 5 6 21 6" }),
          svgEl("path", { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" }),
          svgEl("path", { d: "M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" }),
        ]);
      case "external":
        return svgEl("svg", base, [
          svgEl("path", { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" }),
          svgEl("polyline", { points: "15 3 21 3 21 9" }),
          svgEl("line", { x1: 10, y1: 14, x2: 21, y2: 3 }),
        ]);
      case "laptop":
      default:
        return svgEl("svg", base, [
          svgEl("path", { d: "M4 5h16a1 1 0 0 1 1 1v10H3V6a1 1 0 0 1 1-1z" }),
          svgEl("line", { x1: 2, y1: 19, x2: 22, y2: 19 }),
        ]);
    }
  }

  function detectDeviceKind(name) {
    const lower = String(name || "").toLowerCase();
    if (lower.includes("ipad") || lower.includes("tablet") || lower.includes("galaxy tab")) {
      return "tablet";
    }
    if (
      lower.includes("iphone") ||
      lower.includes("android") ||
      lower.includes("phone") ||
      lower.includes("handy") ||
      lower.includes("pixel") ||
      lower.includes("mobil")
    ) {
      return "phone";
    }
    if (lower.includes("pc") || lower.includes("desktop") || lower.includes("imac") || lower.includes("workstation")) {
      return "desktop";
    }
    return "laptop";
  }

  function detectInitialLanguage() {
    try {
      const saved = localStorage.getItem(STORAGE_LANG_KEY);
      if (saved === "de" || saved === "en") return saved;
    } catch {
      // Ignore storage restrictions
    }
    return "en";
  }

  function detectClientOs() {
    const ua = String(navigator.userAgent || "").toLowerCase();
    const platform = String(navigator.platform || "").toLowerCase();
    if (/iphone|ipad|ipod/.test(ua) || (platform === "macintel" && navigator.maxTouchPoints > 1)) {
      return "ios";
    }
    if (/android/.test(ua)) return "android";
    if (/mac/.test(platform) || /mac os x/.test(ua)) return "macos";
    if (/linux/.test(platform) || /linux/.test(ua)) return "linux";
    return "windows";
  }

  function t(path, vars = {}) {
    const dict = I18N[state.lang] || I18N.en;
    const parts = path.split(".");
    let cur = dict;
    for (const part of parts) {
      if (cur && typeof cur === "object" && part in cur) {
        cur = cur[part];
      } else {
        return path;
      }
    }
    if (typeof cur !== "string") return cur;
    return cur.replace(/\{(\w+)\}/g, (_m, key) => (vars[key] !== undefined ? String(vars[key]) : ""));
  }

  function sanitizeSlug(input, fallback = "vpn") {
    const raw = String(input || "")
      .trim()
      .replace(/ä/gi, "ae")
      .replace(/ö/gi, "oe")
      .replace(/ü/gi, "ue")
      .replace(/ß/g, "ss")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return (raw || fallback).slice(0, 32);
  }

  function buildWireGuardFilename(username, deviceName) {
    const uSlug = sanitizeSlug(username, "user");
    const dSlug = sanitizeSlug(deviceName, "device");
    return `${uSlug}-${dSlug}.conf`;
  }

  function isSafeQrDataUri(uri) {
    return typeof uri === "string" && SAFE_QR_DATA_URI_REGEX.test(uri.trim());
  }

  function normalizeTotpInput(raw) {
    return String(raw || "").replace(/\D+/g, "").slice(0, 6);
  }

  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    const idx = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    const val = n / (1024 ** idx);
    const decimals = idx === 0 ? 0 : val >= 100 ? 0 : val >= 10 ? 1 : 2;
    const locale = state.lang === "de" ? "de-DE" : "en-US";
    return `${val.toLocaleString(locale, {
      minimumFractionDigits: 0,
      maximumFractionDigits: decimals,
    })} ${units[idx]}`;
  }

  function formatDateShort(isoStr) {
    if (!isoStr) return "—";
    const dt = new Date(isoStr);
    if (Number.isNaN(dt.getTime())) return String(isoStr);
    const locale = state.lang === "de" ? "de-DE" : "en-US";
    return dt.toLocaleDateString(locale, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
  }

  function formatHandshake(isoStr) {
    if (!isoStr) return t("wg.neverConnected");
    const dt = new Date(isoStr);
    if (Number.isNaN(dt.getTime())) return String(isoStr);
    const diffSec = Math.max(0, Math.floor((Date.now() - dt.getTime()) / 1000));
    if (diffSec < 60) return t("wg.justNow");
    if (diffSec < 3600) return t("wg.minutesAgo", { n: Math.floor(diffSec / 60) });
    if (diffSec < 86400) return t("wg.hoursAgo", { n: Math.floor(diffSec / 3600) });
    const locale = state.lang === "de" ? "de-DE" : "en-US";
    return dt.toLocaleString(locale, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function triggerTextFileDownload(filename, content, mimeType = "text/plain;charset=utf-8") {
    const blob = new Blob([String(content || "")], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = el("a", {
      href: url,
      download: filename,
      className: "sr-only",
    });
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  async function copyTextToClipboard(text, buttonEl) {
    const str = String(text || "");
    if (!str) return;
    let copied = false;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      try {
        await navigator.clipboard.writeText(str);
        copied = true;
      } catch {
        copied = false;
      }
    }
    if (!copied) {
      const ta = el("textarea", {
        className: "sr-only",
        readonly: true,
      });
      ta.value = str;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        copied = true;
      } catch {
        copied = false;
      }
      ta.remove();
    }
    if (copied && buttonEl) {
      const original = buttonEl.textContent;
      buttonEl.textContent = t("common.copied");
      window.setTimeout(() => {
        buttonEl.textContent = t("common.copy");
        if (!buttonEl.hasAttribute("data-i18n") && original) {
          buttonEl.textContent = original;
        }
      }, 1600);
    }
  }

  function showToast(message, variant = "success") {
    const region = $("toast-region");
    if (!region) return;
    const toast = el("div", {
      className: `toast ${variant === "error" ? "toast-error" : "toast-success"}`,
      text: message,
    });
    region.appendChild(toast);
    window.setTimeout(() => {
      toast.remove();
    }, 4200);
  }

  function showAlert(elementId, message, variant = "error") {
    const box = $(elementId);
    if (!box) return;
    if (!message) {
      box.hidden = true;
      box.textContent = "";
      return;
    }
    box.className = `alert ${variant === "info" ? "alert-info" : "alert-error"}`;
    box.textContent = message;
    box.hidden = false;
  }

  /* ========================================================================
     4. Portal REST API Client
     ======================================================================== */

  class PortalApiError extends Error {
    constructor(status, payload, rawDetail = "") {
      super(rawDetail || `HTTP ${status}`);
      this.name = "PortalApiError";
      this.status = status;
      this.payload = payload;
      this.rawDetail = rawDetail;
    }
  }

  function extractDetailText(payload) {
    if (!payload || typeof payload !== "object") return "";
    if (typeof payload.detail === "string") return payload.detail;
    if (payload.detail && typeof payload.detail === "object") {
      if (typeof payload.detail.message === "string") return payload.detail.message;
      if (typeof payload.detail.code === "string") return payload.detail.code;
      if (Array.isArray(payload.detail) && payload.detail.length > 0) {
        return payload.detail.map((item) => item?.msg || "").filter(Boolean).join("; ");
      }
    }
    if (typeof payload.error === "string") return payload.error;
    if (typeof payload.message === "string") return payload.message;
    return "";
  }

  async function apiFetch(path, { method = "GET", body, allowStatuses = [] } = {}) {
    const headers = {
      [CSRF_HEADER_NAME]: CSRF_HEADER_VALUE,
      Accept: "application/json",
    };
    const fetchOpts = {
      method,
      headers,
      credentials: "same-origin",
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      fetchOpts.body = JSON.stringify(body);
    }

    let res;
    try {
      res = await window.fetch(path, fetchOpts);
    } catch {
      throw new PortalApiError(0, null, "network_error");
    }

    let data = null;
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        data = await res.json();
      } catch {
        data = null;
      }
    }

    if (!res.ok && !allowStatuses.includes(res.status)) {
      throw new PortalApiError(res.status, data, extractDetailText(data));
    }

    return { status: res.status, data };
  }

  function resolveApiErrorMessage(err, context = "general") {
    if (!(err instanceof PortalApiError)) {
      return t("errors.serverError");
    }
    if (err.status === 0) {
      return t("errors.networkError");
    }
    if (err.status === 429) {
      return t("errors.rateLimited");
    }

    const detailLower = String(err.rawDetail || "").toLowerCase();

    if (err.status === 401) {
      if (
        context === "login-totp" ||
        context === "totp-confirm" ||
        (context === "totp-disable" && (detailLower.includes("totp") || detailLower.includes("code") || detailLower.includes("otp")))
      ) {
        return t("errors.invalidTotpCode");
      }
      if (context === "login-credentials" || context === "totp-disable") {
        if (detailLower.includes("totp") || detailLower.includes("otp")) {
          return t("errors.invalidTotpCode");
        }
        return t("errors.invalidCredentials");
      }
      return t("errors.sessionExpired");
    }

    if (err.status === 403) {
      if (context === "login-credentials" || context === "login-totp") {
        return t("errors.forbiddenAccount");
      }
      if (detailLower.includes("totp")) {
        return t("errors.totpEnrollmentRequired");
      }
      if (detailLower.includes("limit") || detailLower.includes("max") || detailLower.includes("quota")) {
        return t("errors.quotaExceeded");
      }
      return t("errors.forbiddenAccount");
    }

    if (err.status === 404) {
      return t("errors.notFound");
    }

    if (err.status === 409) {
      if (detailLower.includes("pool") || detailLower.includes("exhausted")) {
        return t("errors.ipPoolExhausted");
      }
      return t("errors.quotaExceeded");
    }

    if (err.status === 400 || err.status === 422) {
      if (context === "totp-confirm" || context === "login-totp" || detailLower.includes("totp") || detailLower.includes("code")) {
        return t("errors.invalidTotpCode");
      }
      if (detailLower.includes("limit") || detailLower.includes("max") || detailLower.includes("quota")) {
        return t("errors.quotaExceeded");
      }
      if (context === "create-device" || detailLower.includes("device_name")) {
        return t("errors.invalidDeviceName");
      }
      if (context === "totp-disable") {
        return t("errors.invalidCredentials");
      }
    }

    return t("errors.serverError");
  }

  /* ========================================================================
     5. Localization & Static DOM Translation
     ======================================================================== */

  function setLanguage(lang) {
    if (lang !== "de" && lang !== "en") return;
    state.lang = lang;
    try {
      localStorage.setItem(STORAGE_LANG_KEY, lang);
    } catch {
      // Ignore private mode restrictions
    }
    applyTranslations();
  }

  function applyTranslations() {
    document.documentElement.lang = state.lang;
    document.title = t("pageTitle");

    const btnDe = $("lang-btn-de");
    const btnEn = $("lang-btn-en");
    if (btnDe) btnDe.setAttribute("aria-pressed", String(state.lang === "de"));
    if (btnEn) btnEn.setAttribute("aria-pressed", String(state.lang === "en"));

    for (const node of document.querySelectorAll("[data-i18n]")) {
      const key = node.getAttribute("data-i18n");
      if (key) node.textContent = t(key);
    }
    for (const node of document.querySelectorAll("[data-i18n-placeholder]")) {
      const key = node.getAttribute("data-i18n-placeholder");
      if (key) node.setAttribute("placeholder", t(key));
    }
    for (const node of document.querySelectorAll("[data-i18n-aria-label]")) {
      const key = node.getAttribute("data-i18n-aria-label");
      if (key) node.setAttribute("aria-label", t(key));
    }
    for (const node of document.querySelectorAll("[data-i18n-title]")) {
      const key = node.getAttribute("data-i18n-title");
      if (key) node.setAttribute("title", t(key));
    }

    syncPasswordToggleLabel();
    syncLoginStepUi();

    if (state.activeView === "disabled") {
      const msgEl = $("disabled-message");
      if (msgEl) msgEl.textContent = t(state.disabledReasonKey);
    }
    if (state.activeView === "totp-mandatory") {
      const qrImg = $("mandatory-totp-qr-img");
      if (qrImg) qrImg.alt = t("totpGate.qrAlt");
    }
    if (state.activeView === "dashboard" && state.me) {
      renderDashboard();
    }
    if (state.activeModalId === "modal-wg-profile" && state.wgModalContext) {
      populateWgProfileModal(state.wgModalContext);
    }
  }

  /* ========================================================================
     6. View Switching & Session Lifecycle
     ======================================================================== */

  function setView(viewName) {
    state.activeView = viewName;
    const map = {
      loading: "view-loading",
      disabled: "view-disabled",
      login: "view-login",
      "totp-mandatory": "view-totp-mandatory",
      dashboard: "view-dashboard",
    };
    for (const [key, domId] of Object.entries(map)) {
      const section = $(domId);
      if (section) section.hidden = key !== viewName;
    }

    const isAuthed = viewName === "totp-mandatory" || viewName === "dashboard";
    const userBar = $("header-user-bar");
    if (userBar) userBar.hidden = !isAuthed;
    const refreshBtn = $("btn-refresh-dashboard");
    if (refreshBtn) refreshBtn.hidden = viewName !== "dashboard";

    if (viewName === "dashboard") {
      startBackgroundPolling();
    } else {
      stopBackgroundPolling();
    }
  }

  function startBackgroundPolling() {
    stopBackgroundPolling();
    state.pollTimerId = window.setInterval(async () => {
      if (document.visibilityState !== "visible") return;
      if (state.activeView !== "dashboard" || state.activeModalId) return;
      await refreshSessionQuietly();
    }, POLL_INTERVAL_MS);
  }

  function stopBackgroundPolling() {
    if (state.pollTimerId !== null) {
      window.clearInterval(state.pollTimerId);
      state.pollTimerId = null;
    }
  }

  async function bootPortal() {
    setView("loading");
    showAlert("login-alert", "");

    try {
      const infoRes = await apiFetch("/api/v1/portal/info", { allowStatuses: [404] });
      if (infoRes.status === 404 || (infoRes.data && infoRes.data.portal_enabled === false)) {
        state.disabledReasonKey = "disabled.description";
        $("disabled-message").textContent = t("disabled.description");
        setView("disabled");
        return;
      }
      state.portalInfo = infoRes.data;
      updateDomainBadge(infoRes.data?.portal_domain);
    } catch {
      state.disabledReasonKey = "disabled.unreachable";
      $("disabled-message").textContent = t("disabled.unreachable");
      setView("disabled");
      return;
    }

    await loadSessionAndRoute();
  }

  function updateDomainBadge(domain) {
    const badge = $("header-domain-badge");
    if (!badge) return;
    const cleaned = String(domain || "").trim();
    if (cleaned) {
      badge.textContent = cleaned;
      badge.hidden = false;
    } else {
      badge.textContent = "";
      badge.hidden = true;
    }
  }

  async function loadSessionAndRoute() {
    try {
      const meRes = await apiFetch("/api/v1/portal/me", { allowStatuses: [401] });
      if (meRes.status === 401 || !meRes.data || !meRes.data.authenticated) {
        state.me = null;
        resetLoginToStep1();
        setView("login");
        return;
      }
      applyAuthenticatedSession(meRes.data);
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 403) {
        state.me = null;
        resetLoginToStep1();
        setView("login");
        showAlert("login-alert", t("errors.forbiddenAccount"));
        return;
      }
      state.disabledReasonKey = "disabled.unreachable";
      $("disabled-message").textContent = t("disabled.unreachable");
      setView("disabled");
    }
  }

  async function refreshSessionQuietly() {
    try {
      const meRes = await apiFetch("/api/v1/portal/me", { allowStatuses: [401] });
      if (meRes.status === 401 || !meRes.data || !meRes.data.authenticated) {
        handleExpiredSession();
        return false;
      }
      applyAuthenticatedSession(meRes.data);
      return true;
    } catch {
      return false;
    }
  }

  function handleExpiredSession() {
    closeActiveModal();
    state.me = null;
    state.mandatoryTotpLoaded = false;
    state.mandatoryTotpSecret = "";
    resetLoginToStep1();
    setView("login");
    showAlert("login-alert", t("errors.sessionExpired"), "info");
  }

  function applyAuthenticatedSession(meData) {
    state.me = meData;
    updateDomainBadge(state.portalInfo?.portal_domain || meData.endpoint_host);
    renderHeaderUser(meData.user);

    if (meData.totp_setup_required === true) {
      closeActiveModal();
      setView("totp-mandatory");
      if (!state.mandatoryTotpLoaded) {
        void initiateMandatoryTotpSetup();
      }
    } else {
      state.mandatoryTotpLoaded = false;
      state.mandatoryTotpSecret = "";
      setView("dashboard");
      renderDashboard();
    }
  }

  function renderHeaderUser(user) {
    if (!user) return;
    const display = String(user.display_name || user.username || "").trim();
    const uname = String(user.username || "").trim();
    const domain = String(user.domain || "").trim();

    const initials = display
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() || "")
      .join("") || "U";

    $("header-user-initials").textContent = initials;
    $("header-user-name").textContent = display || uname;
    const email = String(user.email || "").trim();
    $("header-user-domain").textContent = domain ? `${uname}@${domain}` : email || uname;
  }

  /* ========================================================================
     7. Login & 2-Step TOTP Challenge
     ======================================================================== */

  function syncPasswordToggleLabel() {
    const pwInput = $("login-password");
    const btn = $("btn-toggle-login-pw");
    const lbl = $("login-pw-toggle-label");
    if (!pwInput || !btn || !lbl) return;
    const visible = pwInput.type === "text";
    btn.setAttribute("aria-pressed", String(visible));
    btn.setAttribute("aria-label", visible ? t("login.hidePassword") : t("login.showPassword"));
    lbl.textContent = visible ? t("login.hideShort") : t("login.showShort");
  }

  function syncLoginStepUi() {
    const isTotp = state.loginStep === "totp";
    const credStep = $("login-step-credentials");
    const totpStep = $("login-step-totp");
    const backBtn = $("btn-login-back");
    const submitText = $("btn-login-submit-text");
    const subtitle = $("login-subtitle");

    if (credStep) credStep.hidden = isTotp;
    if (totpStep) totpStep.hidden = !isTotp;
    if (backBtn) backBtn.hidden = !isTotp;
    if (submitText) {
      submitText.textContent = isTotp ? t("login.verifySubmitBtn") : t("login.submitBtn");
    }
    if (subtitle) {
      subtitle.textContent = isTotp ? t("login.totpStepSubtitle") : t("login.subtitle");
    }
  }

  function resetLoginToStep1() {
    state.loginStep = "credentials";
    state.pendingLoginUsername = "";
    state.pendingLoginPassword = "";
    const pwInput = $("login-password");
    if (pwInput) {
      pwInput.type = "password";
      pwInput.value = "";
    }
    const totpInput = $("login-totp-code");
    if (totpInput) totpInput.value = "";
    syncPasswordToggleLabel();
    syncLoginStepUi();
  }

  function transitionLoginToTotpStep(username, password) {
    state.loginStep = "totp";
    state.pendingLoginUsername = username;
    state.pendingLoginPassword = password;
    $("login-totp-username").textContent = username;
    $("login-totp-code").value = "";
    showAlert("login-alert", "");
    syncLoginStepUi();
    window.requestAnimationFrame(() => {
      $("login-totp-code")?.focus();
    });
  }

  async function handleLoginSubmit(event) {
    event.preventDefault();
    showAlert("login-alert", "");

    const submitBtn = $("btn-login-submit");
    const submitText = $("btn-login-submit-text");

    let username;
    let password;
    let totpCode = null;

    if (state.loginStep === "credentials") {
      username = String($("login-username").value || "").trim();
      password = String($("login-password").value || "");
      if (!username || !password) {
        showAlert("login-alert", t("errors.usernameAndPasswordRequired"));
        (!username ? $("login-username") : $("login-password"))?.focus();
        return;
      }
    } else {
      username = state.pendingLoginUsername;
      password = state.pendingLoginPassword;
      totpCode = normalizeTotpInput($("login-totp-code").value);
      if (!TOTP_CODE_REGEX.test(totpCode)) {
        showAlert("login-alert", t("errors.invalidTotpFormat"));
        $("login-totp-code")?.focus();
        return;
      }
    }

    submitBtn.disabled = true;
    submitBtn.setAttribute("aria-busy", "true");
    submitText.textContent = t("login.submitSubmitting");

    try {
      const res = await apiFetch("/api/v1/portal/auth/login", {
        method: "POST",
        body: {
          username,
          password,
          totp_code: totpCode,
        },
        allowStatuses: [401],
      });

      if (res.data && res.data.totp_verify_required === true && !res.data.authenticated) {
        if (state.loginStep === "totp") {
          showAlert("login-alert", t("errors.invalidTotpCode"));
          $("login-totp-code")?.focus();
        } else {
          transitionLoginToTotpStep(username, password);
        }
        return;
      }

      if (res.status === 401 || !res.data || !res.data.authenticated) {
        const ctx = state.loginStep === "totp" ? "login-totp" : "login-credentials";
        throw new PortalApiError(401, res.data, extractDetailText(res.data) || ctx);
      }

      // Clear sensitive login inputs immediately after session cookie is issued
      resetLoginToStep1();
      $("login-username").value = "";
      await loadSessionAndRoute();
    } catch (err) {
      const ctx = state.loginStep === "totp" ? "login-totp" : "login-credentials";
      showAlert("login-alert", resolveApiErrorMessage(err, ctx));
    } finally {
      submitBtn.disabled = false;
      submitBtn.removeAttribute("aria-busy");
      syncLoginStepUi();
    }
  }

  async function handleLogout() {
    const logoutBtn = $("btn-logout");
    if (logoutBtn) logoutBtn.disabled = true;
    try {
      await apiFetch("/api/v1/portal/auth/logout", { method: "POST", body: {} });
    } catch {
      // Clear local UI state even if network dropped
    } finally {
      if (logoutBtn) logoutBtn.disabled = false;
    }

    closeActiveModal();
    state.me = null;
    state.wgModalContext = null;
    state.deleteTargetDevice = null;
    state.mandatoryTotpSecret = "";
    state.mandatoryTotpLoaded = false;
    state.modalTotpSecret = "";
    resetLoginToStep1();
    showAlert("login-alert", "");
    setView("login");
    window.requestAnimationFrame(() => {
      $("login-username")?.focus();
    });
  }

  /* ========================================================================
     8. TOTP 2FA Flows (Mandatory Gate + Optional Dashboard Enable/Disable)
     ======================================================================== */

  function renderQrAndSecret({ qrImgId, loadingId, secretCodeId, qrDataUri, secret }) {
    const qrImg = $(qrImgId);
    const loadingEl = $(loadingId);
    const secretEl = $(secretCodeId);

    if (secretEl) {
      secretEl.textContent = secret ? formatSecretForDisplay(secret) : "—";
    }

    if (isSafeQrDataUri(qrDataUri)) {
      qrImg.src = qrDataUri.trim();
      qrImg.alt = t("totpGate.qrAlt");
      qrImg.hidden = false;
      if (loadingEl) loadingEl.hidden = true;
      return true;
    }

    qrImg.removeAttribute("src");
    qrImg.hidden = true;
    if (loadingEl) {
      loadingEl.textContent = t("errors.invalidQrPayload");
      loadingEl.hidden = false;
    }
    return false;
  }

  function formatSecretForDisplay(secret) {
    const cleaned = String(secret || "").replace(/\s+/g, "").toUpperCase();
    return cleaned.replace(/(.{4})/g, "$1 ").trim();
  }

  async function initiateMandatoryTotpSetup() {
    showAlert("mandatory-totp-alert", "");
    $("mandatory-totp-qr-img").hidden = true;
    $("mandatory-totp-qr-loading").textContent = t("totpGate.generatingQr");
    $("mandatory-totp-qr-loading").hidden = false;
    $("mandatory-totp-secret").textContent = "—";

    try {
      const { data } = await apiFetch("/api/v1/portal/totp/setup", {
        method: "POST",
        body: {},
      });
      const secret = String(data?.secret || data?.base32_secret || "").trim();
      state.mandatoryTotpSecret = secret;
      state.mandatoryTotpLoaded = true;
      renderQrAndSecret({
        qrImgId: "mandatory-totp-qr-img",
        loadingId: "mandatory-totp-qr-loading",
        secretCodeId: "mandatory-totp-secret",
        qrDataUri: data?.qr_svg_data_uri || data?.qr_data_uri,
        secret,
      });
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showAlert("mandatory-totp-alert", resolveApiErrorMessage(err));
    }
  }

  async function handleMandatoryTotpConfirm(event) {
    event.preventDefault();
    showAlert("mandatory-totp-alert", "");

    const code = normalizeTotpInput($("mandatory-totp-code").value);
    if (!TOTP_CODE_REGEX.test(code)) {
      showAlert("mandatory-totp-alert", t("errors.invalidTotpFormat"));
      $("mandatory-totp-code")?.focus();
      return;
    }

    const btn = $("btn-mandatory-totp-submit");
    btn.disabled = true;
    btn.textContent = t("totpGate.verifyingBtn");

    try {
      await apiFetch("/api/v1/portal/totp/confirm", {
        method: "POST",
        body: { code },
      });
      $("mandatory-totp-code").value = "";
      state.mandatoryTotpSecret = "";
      state.mandatoryTotpLoaded = false;
      await loadSessionAndRoute();
      showToast(t("totpGate.unlockedToast"), "success");
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401 && !String(err.rawDetail || "").toLowerCase().includes("totp") && !String(err.rawDetail || "").toLowerCase().includes("code")) {
        // Check if session actually expired
        const stillAuthed = await refreshSessionQuietly();
        if (!stillAuthed) return;
      }
      showAlert("mandatory-totp-alert", resolveApiErrorMessage(err, "totp-confirm"));
      $("mandatory-totp-code")?.focus();
    } finally {
      btn.disabled = false;
      btn.textContent = t("totpGate.verifyBtn");
    }
  }

  async function openOptionalTotpEnableModal(triggerEl) {
    state.modalTotpSecret = "";
    $("modal-totp-enable-code").value = "";
    showAlert("modal-totp-enable-alert", "");
    $("modal-totp-qr-img").hidden = true;
    $("modal-totp-qr-loading").textContent = t("totpGate.generatingQr");
    $("modal-totp-qr-loading").hidden = false;
    $("modal-totp-secret").textContent = "—";

    openModal("modal-totp-enable", triggerEl);

    try {
      const { data } = await apiFetch("/api/v1/portal/totp/setup", {
        method: "POST",
        body: {},
      });
      const secret = String(data?.secret || data?.base32_secret || "").trim();
      state.modalTotpSecret = secret;
      renderQrAndSecret({
        qrImgId: "modal-totp-qr-img",
        loadingId: "modal-totp-qr-loading",
        secretCodeId: "modal-totp-secret",
        qrDataUri: data?.qr_svg_data_uri || data?.qr_data_uri,
        secret,
      });
      $("modal-totp-enable-code")?.focus();
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showAlert("modal-totp-enable-alert", resolveApiErrorMessage(err));
    }
  }

  async function handleOptionalTotpEnableSubmit(event) {
    event.preventDefault();
    showAlert("modal-totp-enable-alert", "");

    const code = normalizeTotpInput($("modal-totp-enable-code").value);
    if (!TOTP_CODE_REGEX.test(code)) {
      showAlert("modal-totp-enable-alert", t("errors.invalidTotpFormat"));
      $("modal-totp-enable-code")?.focus();
      return;
    }

    const btn = $("btn-submit-totp-enable");
    btn.disabled = true;

    try {
      await apiFetch("/api/v1/portal/totp/confirm", {
        method: "POST",
        body: { code },
      });
      state.modalTotpSecret = "";
      $("modal-totp-enable-code").value = "";
      closeActiveModal();
      await loadSessionAndRoute();
      showToast(t("totpGate.unlockedToast"), "success");
    } catch (err) {
      showAlert("modal-totp-enable-alert", resolveApiErrorMessage(err, "totp-confirm"));
      $("modal-totp-enable-code")?.focus();
    } finally {
      btn.disabled = false;
    }
  }

  function openOptionalTotpDisableModal(triggerEl) {
    $("modal-totp-disable-password").value = "";
    $("modal-totp-disable-code").value = "";
    showAlert("modal-totp-disable-alert", "");
    openModal("modal-totp-disable", triggerEl);
  }

  async function handleOptionalTotpDisableSubmit(event) {
    event.preventDefault();
    showAlert("modal-totp-disable-alert", "");

    const password = String($("modal-totp-disable-password").value || "");
    const code = normalizeTotpInput($("modal-totp-disable-code").value);

    if (!password) {
      showAlert("modal-totp-disable-alert", t("errors.passwordRequired"));
      $("modal-totp-disable-password")?.focus();
      return;
    }
    if (!TOTP_CODE_REGEX.test(code)) {
      showAlert("modal-totp-disable-alert", t("errors.invalidTotpFormat"));
      $("modal-totp-disable-code")?.focus();
      return;
    }

    const btn = $("btn-submit-totp-disable");
    btn.disabled = true;
    btn.textContent = t("totpDisableModal.disablingBtn");

    try {
      await apiFetch("/api/v1/portal/totp/disable", {
        method: "POST",
        body: { password, code },
      });
      $("modal-totp-disable-password").value = "";
      $("modal-totp-disable-code").value = "";
      closeActiveModal();
      await loadSessionAndRoute();
      showToast(t("security.disabledToast"), "success");
    } catch (err) {
      showAlert("modal-totp-disable-alert", resolveApiErrorMessage(err, "totp-disable"));
    } finally {
      btn.disabled = false;
      btn.textContent = t("totpDisableModal.confirmBtn");
    }
  }

  /* ========================================================================
     9. Dashboard Rendering (Summary, WireGuard, OpenVPN, 2FA, Setup Guides)
     ======================================================================== */

  function renderDashboard() {
    const me = state.me;
    if (!me) return;

    // 1. Greeting & Metadata Pills
    const displayName = String(me.user?.display_name || me.user?.username || "").trim();
    $("dashboard-heading").textContent = displayName
      ? t("dashboard.greetingNamed", { name: displayName })
      : t("dashboard.greetingDefault");

    const endpointWrap = $("meta-endpoint-wrap");
    if (me.endpoint_host) {
      $("meta-endpoint-value").textContent = me.endpoint_host;
      endpointWrap.hidden = false;
    } else {
      endpointWrap.hidden = true;
    }

    $("meta-tunnel-value").textContent =
      me.tunnel_mode === "full" ? t("dashboard.routingFull") : t("dashboard.routingSplit");

    const totpWrap = $("meta-totp-wrap");
    if (me.totp_mode === "disabled") {
      totpWrap.hidden = true;
    } else {
      totpWrap.hidden = false;
      $("meta-totp-value").textContent = me.user?.totp_enrolled
        ? t("dashboard.twoFactorActive")
        : t("dashboard.twoFactorOptionalOff");
    }

    // 2. WireGuard Quota, Quick Chips & Devices
    renderWireGuardSection(me);

    // 3. Secondary Panels (OpenVPN Fallback + 2FA Security)
    renderSecondaryPanels(me);

    // 4. Embedded Step-by-Step OS Setup Guides
    renderOsGuides();
  }

  function renderWireGuardSection(me) {
    const devices = Array.isArray(me.devices) ? me.devices : [];
    const used = Number.isInteger(me.quota?.used_devices) ? me.quota.used_devices : devices.length;
    const max = Number.isInteger(me.quota?.max_devices)
      ? me.quota.max_devices
      : Number(state.portalInfo?.max_devices_per_user || 3);
    const quotaFull = max > 0 && used >= max;

    $("wg-quota-count").textContent = t("wg.quotaCountText", { used, max });

    const meter = $("wg-quota-meter");
    meter.replaceChildren();
    meter.setAttribute("aria-valuenow", String(used));
    meter.setAttribute("aria-valuemax", String(Math.max(max, 1)));
    const slotCount = Math.min(Math.max(max, 1), 12);
    for (let i = 0; i < slotCount; i += 1) {
      const filled = max > 0 && i < Math.round((used / max) * slotCount);
      meter.appendChild(
        el("span", {
          className: `quota-slot${filled ? (quotaFull ? " is-full" : " is-used") : ""}`,
        })
      );
    }

    const input = $("device-name-input");
    const createBtn = $("btn-create-device");
    const hint = $("create-device-hint");
    input.disabled = quotaFull;
    createBtn.disabled = quotaFull;
    hint.textContent = quotaFull
      ? t("wg.quotaReachedHint", { max })
      : t("wg.nameRulesHint");

    renderDeviceQuickChips(devices, quotaFull);

    const onlineCount = devices.filter((d) => Boolean(d.online && d.effective_active !== false)).length;
    $("wg-online-summary").textContent =
      devices.length > 0 ? t("wg.onlineSummary", { online: onlineCount, total: devices.length }) : "";

    const emptyState = $("wg-empty-state");
    const grid = $("wg-devices-grid");
    grid.replaceChildren();
    grid.classList.toggle("has-many", devices.length >= 3);

    if (devices.length === 0) {
      emptyState.hidden = false;
      grid.hidden = true;
      return;
    }

    emptyState.hidden = true;
    grid.hidden = false;

    for (const dev of devices) {
      grid.appendChild(buildDeviceCard(dev));
    }
  }

  function renderDeviceQuickChips(existingDevices, disabled) {
    const row = $("device-chips-row");
    row.replaceChildren();
    const presets = t("wg.chips");
    if (!Array.isArray(presets)) return;

    const currentInput = String($("device-name-input").value || "").trim();
    const takenLower = new Set(existingDevices.map((d) => String(d.device_name || "").trim().toLowerCase()));

    for (const preset of presets) {
      const chipBtn = el(
        "button",
        {
          type: "button",
          className: `device-chip${currentInput === preset ? " is-selected" : ""}`,
          disabled,
          text: preset,
          onClick: () => {
            let candidate = preset;
            if (takenLower.has(candidate.toLowerCase())) {
              let n = 2;
              while (takenLower.has(`${preset} ${n}`.toLowerCase()) && n < 20) {
                n += 1;
              }
              candidate = `${preset} ${n}`;
            }
            const input = $("device-name-input");
            input.value = candidate;
            showAlert("create-device-alert", "");
            renderDeviceQuickChips(existingDevices, disabled);
            input.focus();
          },
        }
      );
      row.appendChild(chipBtn);
    }
  }

  function buildDeviceCard(dev) {
    const isActive = dev.effective_active !== false && dev.admin_enabled !== false;
    const isOnline = Boolean(isActive && dev.online);

    let badgeClass = "badge-neutral";
    let badgeText = t("wg.statusOffline");
    if (!isActive) {
      badgeClass = "badge-danger";
      badgeText = t("wg.statusSuspended");
    } else if (isOnline) {
      badgeClass = "badge-success";
      badgeText = t("wg.statusOnline");
    }

    const statusBadge = el("span", { className: `status-badge ${badgeClass}` }, [
      el("span", { className: "status-dot", "aria-hidden": "true" }),
      el("span", { text: badgeText }),
    ]);

    const head = el("div", { className: "device-card-head" }, [
      el("div", { className: "device-title-wrap" }, [
        el("span", { className: "device-kind-icon" }, [createIcon(detectDeviceKind(dev.device_name), 18)]),
        el("div", {}, [
          el("h4", { className: "device-name", text: dev.device_name || "VPN Device" }),
          el("span", {
            className: "device-created",
            text: t("wg.createdOn", { date: formatDateShort(dev.created_at) }),
          }),
        ]),
      ]),
      statusBadge,
    ]);

    const stats = el("div", { className: "device-stats" }, [
      el("div", { className: "stat-item" }, [
        el("span", { className: "stat-label", text: t("wg.tunnelIpLabel") }),
        el("span", { className: "stat-value stat-mono", text: dev.assigned_ip || "—" }),
      ]),
      el("div", { className: "stat-item" }, [
        el("span", { className: "stat-label", text: t("wg.handshakeLabel") }),
        el("span", { className: "stat-value", text: formatHandshake(dev.last_handshake_at) }),
      ]),
      el("div", { className: "stat-item stat-item-wide" }, [
        el("span", { className: "stat-label", text: t("wg.trafficLabel") }),
        el("span", {
          className: "stat-value",
          text: `↓ ${formatBytes(dev.rx_bytes)} · ↑ ${formatBytes(dev.tx_bytes)}`,
        }),
      ]),
    ]);

    const qrBtn = el(
      "button",
      {
        type: "button",
        className: "btn btn-secondary btn-sm",
        onClick: (e) => void handleViewDeviceProfile(dev, e.currentTarget),
      },
      [createIcon("qr", 15), el("span", { text: t("wg.profileQrBtn") })]
    );

    const removeBtn = el(
      "button",
      {
        type: "button",
        className: "btn btn-danger-outline btn-sm",
        onClick: (e) => openDeleteDeviceModal(dev, e.currentTarget),
      },
      [createIcon("trash", 15), el("span", { text: t("wg.removeDeviceBtn") })]
    );

    return el(
      "article",
      {
        className: `device-card${isOnline ? " is-online" : ""}`,
        role: "listitem",
      },
      [head, stats, el("div", { className: "device-card-actions" }, [qrBtn, removeBtn])]
    );
  }

  function renderSecondaryPanels(me) {
    const grid = $("secondary-grid");
    const ovpnPanel = $("panel-openvpn");
    const totpPanel = $("panel-totp-security");

    const showOvpn = Boolean(me.openvpn_enabled);
    const showTotp = me.totp_mode === "optional" || me.totp_mode === "required";

    ovpnPanel.hidden = !showOvpn;
    totpPanel.hidden = !showTotp;

    if (showOvpn) {
      const totpCallout = $("ovpn-totp-callout");
      const enrollFirstBtn = $("btn-ovpn-setup-totp");
      totpCallout.hidden = !me.ovpn_totp_required;
      enrollFirstBtn.hidden = !(
        me.ovpn_totp_required &&
        me.totp_mode === "optional" &&
        !me.user?.totp_enrolled
      );
    }

    if (showTotp) {
      const enrolled = Boolean(me.user?.totp_enrolled);
      const badge = $("totp-card-badge");
      const desc = $("totp-card-desc");
      const policyNote = $("totp-policy-note");
      const actionsWrap = $("totp-optional-actions");
      const enableBtn = $("btn-open-totp-enable");
      const disableBtn = $("btn-open-totp-disable");

      if (me.totp_mode === "required") {
        badge.className = "status-badge badge-success";
        badge.textContent = t("security.badgeRequired");
        desc.textContent = t("security.descRequiredOn");
        policyNote.hidden = false;
        actionsWrap.hidden = true;
      } else {
        policyNote.hidden = true;
        actionsWrap.hidden = false;
        if (enrolled) {
          badge.className = "status-badge badge-success";
          badge.textContent = t("security.badgeActive");
          desc.textContent = t("security.descOptionalOn");
          enableBtn.hidden = true;
          disableBtn.hidden = false;
        } else {
          badge.className = "status-badge badge-neutral";
          badge.textContent = t("security.badgeInactive");
          desc.textContent = t("security.descOptionalOff");
          enableBtn.hidden = false;
          disableBtn.hidden = true;
        }
      }
    }

    const visibleCount = (showOvpn ? 1 : 0) + (showTotp ? 1 : 0);
    grid.hidden = visibleCount === 0;
    grid.classList.toggle("is-single", visibleCount === 1);
  }

  /* ========================================================================
     10. WireGuard & OpenVPN Actions
     ======================================================================== */

  async function handleCreateDeviceSubmit(event) {
    event.preventDefault();
    showAlert("create-device-alert", "");

    const input = $("device-name-input");
    const deviceName = String(input.value || "").trim();
    if (!deviceName || !DEVICE_NAME_REGEX.test(deviceName)) {
      showAlert("create-device-alert", t("errors.invalidDeviceName"));
      input.focus();
      return;
    }

    const btn = $("btn-create-device");
    const btnSpan = btn.querySelector("span");
    btn.disabled = true;
    if (btnSpan) btnSpan.textContent = t("wg.creatingBtn");

    try {
      const { data } = await apiFetch("/api/v1/portal/devices", {
        method: "POST",
        body: { device_name: deviceName },
      });

      input.value = "";
      const createdPeer = data?.peer || data?.device || {};
      const username = state.me?.user?.username || createdPeer.username || "user";
      const resolvedName = createdPeer.device_name || deviceName;
      const filename = buildWireGuardFilename(username, resolvedName);

      await refreshSessionQuietly();
      showToast(t("wg.deviceCreatedToast", { name: resolvedName }), "success");

      openWgProfileModal(
        {
          deviceName: resolvedName,
          assignedIp: createdPeer.assigned_ip || "",
          filename,
          configText: String(data?.config_text || ""),
          qrSvgDataUri: String(data?.qr_svg_data_uri || ""),
        },
        btn
      );
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showAlert("create-device-alert", resolveApiErrorMessage(err, "create-device"));
    } finally {
      if (btnSpan) btnSpan.textContent = t("wg.createBtn");
      if (state.me) renderWireGuardSection(state.me);
    }
  }

  async function handleViewDeviceProfile(dev, triggerEl) {
    if (!dev || !dev.id) return;
    if (triggerEl) triggerEl.disabled = true;
    try {
      const { data } = await apiFetch(
        `/api/v1/portal/devices/${encodeURIComponent(dev.id)}/wireguard`
      );
      const username = data?.username || state.me?.user?.username || "user";
      const resolvedName = data?.device_name || dev.device_name || "device";
      openWgProfileModal(
        {
          deviceName: resolvedName,
          assignedIp: data?.assigned_ip || dev.assigned_ip || "",
          filename: buildWireGuardFilename(username, resolvedName),
          configText: String(data?.config_text || ""),
          qrSvgDataUri: String(data?.qr_svg_data_uri || ""),
        },
        triggerEl
      );
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showToast(resolveApiErrorMessage(err), "error");
    } finally {
      if (triggerEl) triggerEl.disabled = false;
    }
  }

  function openWgProfileModal(ctx, triggerEl) {
    state.wgModalContext = ctx;
    $("modal-wg-details").open = false;
    populateWgProfileModal(ctx);
    openModal("modal-wg-profile", triggerEl);
  }

  function populateWgProfileModal(ctx) {
    $("modal-wg-title").textContent = t("wgModal.titleWithDevice", { name: ctx.deviceName });
    $("modal-wg-subtitle").textContent = ctx.assignedIp ? `${t("wg.tunnelIpLabel")}: ${ctx.assignedIp}` : ctx.filename;
    $("modal-wg-filename").textContent = ctx.filename;
    $("modal-wg-conf-text").textContent = ctx.configText;

    const qrImg = $("modal-wg-qr-img");
    if (isSafeQrDataUri(ctx.qrSvgDataUri)) {
      qrImg.src = ctx.qrSvgDataUri.trim();
      qrImg.alt = t("wgModal.qrAlt");
      qrImg.hidden = false;
    } else {
      qrImg.removeAttribute("src");
      qrImg.hidden = true;
    }
  }

  function openDeleteDeviceModal(dev, triggerEl) {
    state.deleteTargetDevice = dev;
    $("modal-delete-device-name").textContent = dev.device_name || "VPN Device";
    $("modal-delete-device-ip").textContent = dev.assigned_ip || "";
    showAlert("modal-delete-alert", "");
    openModal("modal-delete-device", triggerEl);
  }

  async function handleConfirmDeleteDevice() {
    const target = state.deleteTargetDevice;
    if (!target || !target.id) return;

    const btn = $("btn-confirm-delete-device");
    btn.disabled = true;
    btn.textContent = t("deleteModal.deletingBtn");
    showAlert("modal-delete-alert", "");

    try {
      await apiFetch(`/api/v1/portal/devices/${encodeURIComponent(target.id)}`, {
        method: "DELETE",
      });
      const removedName = target.device_name || "VPN";
      state.deleteTargetDevice = null;
      closeActiveModal();
      await refreshSessionQuietly();
      showToast(t("wg.deviceRemovedToast", { name: removedName }), "success");
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showAlert("modal-delete-alert", resolveApiErrorMessage(err));
    } finally {
      btn.disabled = false;
      btn.textContent = t("deleteModal.confirmBtn");
    }
  }

  async function handleDownloadOpenVpnProfile() {
    showAlert("ovpn-alert", "");
    const btn = $("btn-download-ovpn");
    const span = btn.querySelector("span");
    btn.disabled = true;
    if (span) span.textContent = t("ovpn.downloadingBtn");

    try {
      const { data } = await apiFetch("/api/v1/portal/openvpn/profile");
      const username = state.me?.user?.username || "user";
      const rawFilename = String(data?.filename || "").trim();
      const safeFilename = rawFilename
        ? rawFilename.replace(/[\\/:*?"<>|]+/g, "_")
        : `${sanitizeSlug(username, "user")}-openvpn.ovpn`;
      const ovpnText = String(data?.ovpn_text || data?.config_text || "");
      triggerTextFileDownload(safeFilename, ovpnText, "application/x-openvpn-profile;charset=utf-8");
      showToast(t("ovpn.downloadedToast", { filename: safeFilename }), "success");
    } catch (err) {
      if (err instanceof PortalApiError && err.status === 401) {
        handleExpiredSession();
        return;
      }
      showAlert("ovpn-alert", resolveApiErrorMessage(err));
    } finally {
      btn.disabled = false;
      if (span) span.textContent = t("ovpn.downloadBtn");
    }
  }

  /* ========================================================================
     11. Embedded Interactive OS Setup Guides (WAI-ARIA Tabs)
     ======================================================================== */

  function selectOsTab(osKey, moveFocus = false) {
    if (!OFFICIAL_LINKS[osKey]) return;
    state.selectedOs = osKey;

    const tabs = document.querySelectorAll(".os-tab");
    for (const tab of tabs) {
      const isMatch = tab.dataset.os === osKey;
      tab.setAttribute("aria-selected", String(isMatch));
      tab.tabIndex = isMatch ? 0 : -1;
      if (isMatch && moveFocus) {
        tab.focus();
      }
    }

    const panel = $("guide-tabpanel");
    if (panel) {
      panel.setAttribute("aria-labelledby", `tab-${osKey}`);
    }
    renderOsGuides();
  }

  function renderOsGuides() {
    const osKey = state.selectedOs;
    const links = OFFICIAL_LINKS[osKey] || OFFICIAL_LINKS.windows;
    const osGuide = t(`guides.os.${osKey}`);
    const panel = $("guide-tabpanel");
    if (!panel || !osGuide || typeof osGuide !== "object") return;

    // Sync tab aria-selected state on initial render
    for (const tab of document.querySelectorAll(".os-tab")) {
      const isMatch = tab.dataset.os === osKey;
      tab.setAttribute("aria-selected", String(isMatch));
      tab.tabIndex = isMatch ? 0 : -1;
    }
    panel.setAttribute("aria-labelledby", `tab-${osKey}`);

    const wgStepsList = el("ol", { className: "guide-steps" });
    for (const stepText of osGuide.wgSteps || []) {
      wgStepsList.appendChild(el("li", { text: stepText }));
    }

    const wgTopChildren = [
      el("h3", { className: "guide-box-title", text: t("guides.wgBoxTitle") }),
      wgStepsList,
    ];
    if (osGuide.wgCli) {
      wgTopChildren.push(el("div", { className: "guide-cli-snippet", text: osGuide.wgCli }));
    }

    const wgBox = el("div", { className: "guide-box" }, [
      el("div", {}, wgTopChildren),
      el("div", { className: "guide-links" }, [
        el(
          "a",
          {
            href: links.wireguard,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "btn btn-secondary btn-sm",
          },
          [el("span", { text: t("guides.downloadWgBtn") }), createIcon("external", 14)]
        ),
      ]),
    ]);

    const ovpnStepsList = el("ol", { className: "guide-steps" });
    for (const stepText of osGuide.ovpnSteps || []) {
      ovpnStepsList.appendChild(el("li", { text: stepText }));
    }

    const ovpnTopChildren = [
      el("h3", { className: "guide-box-title", text: t("guides.ovpnBoxTitle") }),
      ovpnStepsList,
    ];
    if (state.me?.ovpn_totp_required) {
      ovpnTopChildren.push(
        el("p", {
          className: "field-hint",
          text: t("guides.ovpnTotpReminder"),
        })
      );
    }

    const ovpnBox = el("div", { className: "guide-box" }, [
      el("div", {}, ovpnTopChildren),
      el("div", { className: "guide-links" }, [
        el(
          "a",
          {
            href: links.openvpn,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "btn btn-secondary btn-sm",
          },
          [el("span", { text: t("guides.downloadOvpnBtn") }), createIcon("external", 14)]
        ),
      ]),
    ]);

    const columns = el("div", { className: "guide-columns has-two" }, [wgBox, ovpnBox]);
    panel.replaceChildren(columns);
  }

  /* ========================================================================
     12. Accessible Modal Manager (Focus Trap, Escape, Restore Focus)
     ======================================================================== */

  const MODAL_IDS = [
    "modal-wg-profile",
    "modal-delete-device",
    "modal-totp-enable",
    "modal-totp-disable",
  ];

  function openModal(modalId, triggerEl) {
    const backdrop = $("modal-backdrop");
    const target = $(modalId);
    if (!backdrop || !target) return;

    state.lastFocusedElement = triggerEl instanceof HTMLElement ? triggerEl : document.activeElement;
    state.activeModalId = modalId;

    for (const id of MODAL_IDS) {
      const dialog = $(id);
      if (dialog) dialog.hidden = id !== modalId;
    }

    backdrop.hidden = false;
    document.body.classList.add("modal-open");

    window.requestAnimationFrame(() => {
      const focusables = getFocusableElements(target);
      const preferred =
        target.querySelector("input:not([disabled]), .btn-primary:not([disabled]), .btn-danger:not([disabled])") ||
        focusables[0];
      if (preferred instanceof HTMLElement) {
        preferred.focus();
      }
    });
  }

  function closeActiveModal() {
    if (!state.activeModalId) return;
    const backdrop = $("modal-backdrop");
    for (const id of MODAL_IDS) {
      const dialog = $(id);
      if (dialog) dialog.hidden = true;
    }
    if (backdrop) backdrop.hidden = true;
    document.body.classList.remove("modal-open");

    // Clear sensitive modal state when closing
    if (state.activeModalId === "modal-wg-profile") {
      $("modal-wg-conf-text").textContent = "";
      $("modal-wg-qr-img").removeAttribute("src");
      state.wgModalContext = null;
    }
    if (state.activeModalId === "modal-totp-disable") {
      $("modal-totp-disable-password").value = "";
      $("modal-totp-disable-code").value = "";
    }

    state.activeModalId = null;
    if (state.lastFocusedElement && document.contains(state.lastFocusedElement)) {
      state.lastFocusedElement.focus();
    }
    state.lastFocusedElement = null;
  }

  function getFocusableElements(container) {
    return Array.from(
      container.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((node) => !node.closest("[hidden]"));
  }

  function handleGlobalKeydown(event) {
    if (!state.activeModalId) return;
    const dialog = $(state.activeModalId);
    if (!dialog) return;

    if (event.key === "Escape") {
      event.preventDefault();
      closeActiveModal();
      return;
    }

    if (event.key === "Tab") {
      const focusables = getFocusableElements(dialog);
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  }

  /* ========================================================================
     13. Event Wiring & Initialization
     ======================================================================== */

  function bindEvents() {
    // Language Switcher
    $("lang-btn-de").addEventListener("click", () => setLanguage("de"));
    $("lang-btn-en").addEventListener("click", () => setLanguage("en"));

    // Header Actions
    $("btn-logout").addEventListener("click", () => void handleLogout());
    $("btn-refresh-dashboard").addEventListener("click", async () => {
      const ok = await refreshSessionQuietly();
      if (ok) showToast(t("dashboard.refreshedToast"), "success");
    });
    $("btn-retry-boot").addEventListener("click", () => void bootPortal());

    // Login Form & Controls
    $("login-form").addEventListener("submit", (e) => void handleLoginSubmit(e));
    $("btn-login-back").addEventListener("click", () => {
      resetLoginToStep1();
      showAlert("login-alert", "");
      $("login-password")?.focus();
    });
    $("btn-toggle-login-pw").addEventListener("click", () => {
      const pw = $("login-password");
      pw.type = pw.type === "password" ? "text" : "password";
      syncPasswordToggleLabel();
      pw.focus();
    });

    // Sanitize numeric 6-digit TOTP inputs as the user types or pastes
    for (const inputId of [
      "login-totp-code",
      "mandatory-totp-code",
      "modal-totp-enable-code",
      "modal-totp-disable-code",
    ]) {
      const elInput = $(inputId);
      elInput.addEventListener("input", () => {
        const cleaned = normalizeTotpInput(elInput.value);
        if (elInput.value !== cleaned) elInput.value = cleaned;
      });
    }

    // Mandatory 2FA Wizard
    $("mandatory-totp-form").addEventListener("submit", (e) => void handleMandatoryTotpConfirm(e));
    $("btn-reload-mandatory-totp").addEventListener("click", () => void initiateMandatoryTotpSetup());
    $("btn-copy-mandatory-secret").addEventListener("click", (e) => {
      void copyTextToClipboard(state.mandatoryTotpSecret, e.currentTarget);
    });

    // WireGuard Device Creation
    $("create-device-form").addEventListener("submit", (e) => void handleCreateDeviceSubmit(e));
    $("device-name-input").addEventListener("input", () => {
      if (state.me) {
        renderDeviceQuickChips(
          Array.isArray(state.me.devices) ? state.me.devices : [],
          $("device-name-input").disabled
        );
      }
    });

    // OpenVPN Download & 2FA Shortcut
    $("btn-download-ovpn").addEventListener("click", () => void handleDownloadOpenVpnProfile());
    $("btn-ovpn-setup-totp").addEventListener("click", (e) => {
      void openOptionalTotpEnableModal(e.currentTarget);
    });

    // Optional 2FA Security Card & Modals
    $("btn-open-totp-enable").addEventListener("click", (e) => {
      void openOptionalTotpEnableModal(e.currentTarget);
    });
    $("btn-open-totp-disable").addEventListener("click", (e) => {
      openOptionalTotpDisableModal(e.currentTarget);
    });
    $("modal-totp-enable-form").addEventListener("submit", (e) => void handleOptionalTotpEnableSubmit(e));
    $("btn-copy-modal-secret").addEventListener("click", (e) => {
      void copyTextToClipboard(state.modalTotpSecret, e.currentTarget);
    });
    $("modal-totp-disable-form").addEventListener("submit", (e) => void handleOptionalTotpDisableSubmit(e));

    // WireGuard Profile Modal Controls
    $("btn-download-wg-conf").addEventListener("click", () => {
      const ctx = state.wgModalContext;
      if (!ctx) return;
      triggerTextFileDownload(ctx.filename, ctx.configText, "text/plain;charset=utf-8");
      showToast(t("wgModal.downloadedToast", { filename: ctx.filename }), "success");
    });
    $("btn-copy-wg-conf").addEventListener("click", (e) => {
      if (!state.wgModalContext) return;
      void copyTextToClipboard(state.wgModalContext.configText, e.currentTarget);
    });

    // Delete Device Modal Confirm
    $("btn-confirm-delete-device").addEventListener("click", () => void handleConfirmDeleteDevice());

    // Close Modal Buttons & Backdrop Click
    for (const closeBtnId of [
      "btn-close-wg-modal",
      "btn-done-wg-modal",
      "btn-close-delete-modal",
      "btn-cancel-delete-modal",
      "btn-close-totp-enable",
      "btn-cancel-totp-enable",
      "btn-close-totp-disable",
      "btn-cancel-totp-disable",
    ]) {
      $(closeBtnId).addEventListener("click", () => closeActiveModal());
    }

    let mouseDownOnBackdrop = false;
    const backdrop = $("modal-backdrop");
    backdrop.addEventListener("mousedown", (e) => {
      mouseDownOnBackdrop = e.target === backdrop;
    });
    backdrop.addEventListener("click", (e) => {
      if (mouseDownOnBackdrop && e.target === backdrop) {
        closeActiveModal();
      }
      mouseDownOnBackdrop = false;
    });

    document.addEventListener("keydown", handleGlobalKeydown);

    // WAI-ARIA OS Setup Guide Tabs (Click + Arrow/Home/End keys)
    const osOrder = ["windows", "macos", "ios", "android", "linux"];
    for (const tab of document.querySelectorAll(".os-tab")) {
      tab.addEventListener("click", () => {
        selectOsTab(tab.dataset.os, false);
      });
      tab.addEventListener("keydown", (e) => {
        const idx = osOrder.indexOf(tab.dataset.os);
        if (idx === -1) return;
        let nextIdx = -1;
        if (e.key === "ArrowRight") nextIdx = (idx + 1) % osOrder.length;
        else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + osOrder.length) % osOrder.length;
        else if (e.key === "Home") nextIdx = 0;
        else if (e.key === "End") nextIdx = osOrder.length - 1;
        if (nextIdx !== -1) {
          e.preventDefault();
          selectOsTab(osOrder[nextIdx], true);
        }
      });
    }
  }

  function init() {
    applyTranslations();
    bindEvents();
    void bootPortal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
