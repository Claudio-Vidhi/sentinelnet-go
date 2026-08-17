package audit

import (
	"fmt"
	"strings"
)

var Messages = map[string]map[string]string{
	"engine.nothing_to_assess": {
		"en": "Nothing to assess: the supplied text is empty, or not recognised as a network configuration.",
		"it": "Nessuna configurazione da valutare: il testo fornito e' vuoto o non riconosciuto come configurazione di rete.",
	},
	"ev.block_empty": {
		"en": "block present but with no entries",
		"it": "blocco presente ma privo di voci",
	},
	"ev.default_admin_account": {
		"en": "default \u00abadmin\u00bb administrative account present",
		"it": "account amministrativo di default \u00abadmin\u00bb presente",
	},
	"ev.no_block": {
		"en": "\u00ab{what}\u00bb block absent",
		"it": "blocco \u00ab{what}\u00bb assente",
	},
	"ev.no_directive": {
		"en": "no \u00ab{what}\u00bb in the configuration",
		"it": "nessun \u00ab{what}\u00bb in configurazione",
	},
	"ev.no_transport_input": {
		"en": "no \u00abtransport input\u00bb: the default allows every protocol, telnet included",
		"it": "nessun \u00abtransport input\u00bb: il default ammette ogni protocollo, telnet compreso",
	},
	"ev.no_trusthost": {
		"en": "no \u00abtrusthost\u00bb defined for this account",
		"it": "nessun \u00abtrusthost\u00bb definito per l'account",
	},
	"ev.not_set_default": {
		"en": "\u00ab{what}\u00bb not set: the platform default applies",
		"it": "\u00ab{what}\u00bb non impostato: vale il default di piattaforma",
	},
	"ev.not_set_default_on": {
		"en": "no \u00ab{what}\u00bb: the feature stays on by default",
		"it": "nessun \u00ab{what}\u00bb: la funzione resta attiva per default",
	},
	"ev.not_set_default_value": {
		"en": "\u00ab{what}\u00bb not set: the default {value} applies",
		"it": "\u00ab{what}\u00bb non impostato: vale il default {value}",
	},
	"ev.ntp_custom_without_server": {
		"en": "\u00abtype custom\u00bb with no server under \u00abconfig ntpserver\u00bb",
		"it": "\u00abtype custom\u00bb senza alcun server in \u00abconfig ntpserver\u00bb",
	},
	"ev.snmp_v1v2c_active": {
		"en": "SNMP v1/v2c community active",
		"it": "community SNMP v1/v2c attiva",
	},
	"fos.admin_port.default": {
		"en": "Administrative ports left on their defaults ({count} of 2): not a vulnerability in itself, but mass scans find these first.",
		"it": "Porte amministrative sui valori di default ({count} su 2): non e' una vulnerabilita' di per se', ma le scansioni di massa le trovano per prime.",
	},
	"fos.admin_port.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: administrative ports cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare le porte amministrative.",
	},
	"fos.admin_port.ok": {
		"en": "Administrative ports moved off the defaults.",
		"it": "Porte amministrative spostate dai default.",
	},
	"fos.admin_ports.exposed": {
		"en": "Administrative ports (SSH 22 / RDP 3389) reachable from the Internet in {count} policies.",
		"it": "Porte amministrative (SSH 22 / RDP 3389) raggiungibili da Internet in {count} policy.",
	},
	"fos.admin_ports.ok": {
		"en": "No direct exposure of SSH/RDP towards public networks.",
		"it": "Nessuna esposizione diretta di SSH/RDP verso reti pubbliche.",
	},
	"fos.any_any.found": {
		"en": "Found {count} policies accepting any-to-any traffic on any service.",
		"it": "Trovate {count} policy che accettano traffico any-to-any su qualunque servizio.",
	},
	"fos.any_any.ok": {
		"en": "No any-to-any policy: source, destination and service are always specified.",
		"it": "Nessuna policy any-to-any: sorgente, destinazione e servizio sono sempre specificati.",
	},
	"fos.auto_install.enabled": {
		"en": "Automatic install from USB enabled: anyone with physical access can replace the configuration or the firmware at boot.",
		"it": "Installazione automatica da chiavetta USB attiva: chi ha accesso fisico puo' sostituire configurazione o firmware al riavvio.",
	},
	"fos.auto_install.no_section": {
		"en": "\u00abconfig system auto-install\u00bb section absent: the platform default applies.",
		"it": "Sezione \u00abconfig system auto-install\u00bb assente: vale il default della piattaforma.",
	},
	"fos.auto_install.ok": {
		"en": "Automatic install from USB disabled.",
		"it": "Installazione automatica da USB disabilitata.",
	},
	"fos.banners.missing": {
		"en": "Login banners missing ({count} of 2): no legal notice before or after authentication.",
		"it": "Banner di accesso mancanti ({count} su 2): nessuna avvertenza legale prima o dopo l'autenticazione.",
	},
	"fos.banners.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: login banners cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare i banner di accesso.",
	},
	"fos.banners.ok": {
		"en": "Pre-login and post-login banners both enabled.",
		"it": "Banner pre-login e post-login entrambi attivi.",
	},
	"fos.boundary.found": {
		"en": "Found {count} inbound policies from WAN towards any internal destination.",
		"it": "Trovate {count} policy in ingresso da WAN verso qualunque destinazione interna.",
	},
	"fos.boundary.ok": {
		"en": "No inbound policy from WAN towards a catch-all destination.",
		"it": "Nessuna policy in ingresso da WAN verso destinazioni generiche.",
	},
	"fos.comments.missing": {
		"en": "{count} policies with no comment: with no recorded reason nobody dares remove them, so they stay forever.",
		"it": "{count} policy prive di commento: senza una motivazione registrata nessuno se la sente di rimuoverle, e restano per sempre.",
	},
	"fos.comments.ok": {
		"en": "Every policy is documented.",
		"it": "Tutte le policy sono documentate.",
	},
	"fos.cpu_log.bad": {
		"en": "Single-core saturation not logged: a process pinning one CPU goes unnoticed while the average load stays low.",
		"it": "Saturazione di un singolo core non registrata: un processo che satura una CPU passa inosservato finche' il carico medio resta basso.",
	},
	"fos.cpu_log.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the CPU saturation alarm cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare l'allarme di saturazione CPU.",
	},
	"fos.cpu_log.not_set": {
		"en": "\u00ablog-single-cpu-high\u00bb not set: the platform default applies.",
		"it": "\u00ablog-single-cpu-high\u00bb non impostato: vale il default della piattaforma.",
	},
	"fos.cpu_log.ok": {
		"en": "Single-CPU saturation alarm enabled.",
		"it": "Allarme di saturazione di una singola CPU attivo.",
	},
	"fos.defaults.found": {
		"en": "Factory defaults or an unenforced password policy detected ({count} findings).",
		"it": "Rilevati default di fabbrica o policy password non applicata ({count} riscontri).",
	},
	"fos.defaults.no_section": {
		"en": "Neither \u00abconfig system admin\u00bb nor \u00abconfig system password-policy\u00bb present: factory defaults cannot be assessed.",
		"it": "Ne' \u00abconfig system admin\u00bb ne' \u00abconfig system password-policy\u00bb presenti: impossibile valutare i default di fabbrica.",
	},
	"fos.defaults.ok": {
		"en": "No default account, and the password policy is enforced.",
		"it": "Nessun account di default e policy password attiva.",
	},
	"fos.dns.no_section": {
		"en": "No DNS server configured: the \u00abconfig system dns\u00bb section does not exist.",
		"it": "Nessun server DNS configurato: la sezione \u00abconfig system dns\u00bb non esiste.",
	},
	"fos.dns.no_server": {
		"en": "DNS block present but no resolver defined.",
		"it": "Blocco DNS presente ma nessun server risolutore definito.",
	},
	"fos.dns.ok": {
		"en": "Two DNS servers configured.",
		"it": "Due server DNS configurati.",
	},
	"fos.dns.single": {
		"en": "Only one DNS server configured: resolution stops if that server goes silent.",
		"it": "Un solo server DNS configurato: la risoluzione si ferma se quel server non risponde.",
	},
	"fos.event_log.bad": {
		"en": "System event logging disabled: logins, configuration changes and HA failovers leave no trace.",
		"it": "Registrazione degli eventi di sistema disabilitata: login, modifiche di configurazione e failover HA non lasciano traccia.",
	},
	"fos.event_log.no_section": {
		"en": "\u00abconfig log eventfilter\u00bb section absent: event logging cannot be assessed.",
		"it": "Sezione \u00abconfig log eventfilter\u00bb assente: impossibile valutare la registrazione degli eventi.",
	},
	"fos.event_log.not_set": {
		"en": "\u00abevent\u00bb not set: the platform default applies.",
		"it": "\u00abevent\u00bb non impostato: vale il default della piattaforma.",
	},
	"fos.event_log.ok": {
		"en": "System event logging enabled.",
		"it": "Registrazione degli eventi di sistema attiva.",
	},
	"fos.gui_hostname.bad": {
		"en": "Hostname shown on the login page: anyone who reaches the GUI reads the device name before authenticating.",
		"it": "Hostname mostrato nella pagina di login: chiunque raggiunga la GUI legge il nome dell'apparato prima di autenticarsi.",
	},
	"fos.gui_hostname.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: hostname display cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare la visualizzazione dell'hostname.",
	},
	"fos.gui_hostname.not_set": {
		"en": "\u00abgui-display-hostname\u00bb not set: the platform default applies.",
		"it": "\u00abgui-display-hostname\u00bb non impostato: vale il default della piattaforma.",
	},
	"fos.gui_hostname.ok": {
		"en": "Hostname not shown on the login page.",
		"it": "Hostname non mostrato nella pagina di login.",
	},
	"fos.ha.no_monitor": {
		"en": "HA cluster with no monitored interfaces: failover does not trigger when a data link drops, only when the node itself goes down.",
		"it": "Cluster HA senza interfacce monitorate: il failover non scatta se cade un collegamento dati, solo se cade il nodo.",
	},
	"fos.ha.no_section": {
		"en": "\u00abconfig system ha\u00bb section absent: the device is not in a high-availability configuration.",
		"it": "Sezione \u00abconfig system ha\u00bb assente: apparato non in configurazione di alta disponibilita'.",
	},
	"fos.ha.ok": {
		"en": "HA cluster in \u00ab{mode}\u00bb mode with {count} monitored interfaces.",
		"it": "Cluster HA in modalita' \u00ab{mode}\u00bb con {count} interfacce monitorate.",
	},
	"fos.ha.standalone": {
		"en": "HA in standalone mode: no cluster to assess.",
		"it": "HA in modalita' standalone: nessun cluster da valutare.",
	},
	"fos.hostname.factory": {
		"en": "Hostname still the factory one.",
		"it": "Hostname ancora quello di fabbrica.",
	},
	"fos.hostname.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the hostname cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare l'hostname.",
	},
	"fos.hostname.not_set": {
		"en": "Hostname not set: the device keeps its factory name and logs do not tell it apart from the others.",
		"it": "Hostname non impostato: l'apparato resta col nome di fabbrica e i log non lo distinguono dagli altri.",
	},
	"fos.hostname.ok": {
		"en": "Hostname customised.",
		"it": "Hostname personalizzato.",
	},
	"fos.https_redirect.bad": {
		"en": "HTTPS redirect disabled: the GUI stays reachable in cleartext wherever HTTP is allowed.",
		"it": "Redirect HTTPS disabilitato: la GUI resta raggiungibile in chiaro sugli indirizzi dove HTTP e' ammesso.",
	},
	"fos.https_redirect.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the HTTPS redirect cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare il redirect HTTPS.",
	},
	"fos.https_redirect.not_set": {
		"en": "\u00abadmin-https-redirect\u00bb not set: the platform default applies.",
		"it": "\u00abadmin-https-redirect\u00bb non impostato: vale il default della piattaforma.",
	},
	"fos.https_redirect.ok": {
		"en": "HTTP-to-HTTPS redirect enabled on the GUI.",
		"it": "Redirect da HTTP a HTTPS attivo sulla GUI.",
	},
	"fos.idle.disabled": {
		"en": "Administrative timeout disabled (0): sessions never expire.",
		"it": "Timeout amministrativo disabilitato (0): le sessioni non scadono mai.",
	},
	"fos.idle.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the administrative timeout cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare il timeout amministrativo.",
	},
	"fos.idle.not_set": {
		"en": "\u00abadmintimeout\u00bb not configured: the platform default applies.",
		"it": "\u00abadmintimeout\u00bb non configurato: si applica il default della piattaforma.",
	},
	"fos.idle.ok": {
		"en": "Administrative idle timeout set to {value} minutes.",
		"it": "Timeout di inattivita' amministrativa configurato a {value} minuti.",
	},
	"fos.idle.too_high": {
		"en": "Administrative timeout too high ({value} minutes, recommended maximum {max}).",
		"it": "Timeout amministrativo troppo alto ({value} minuti, massimo consigliato {max}).",
	},
	"fos.idle.unreadable": {
		"en": "\u00abadmintimeout\u00bb value cannot be read as a number.",
		"it": "Valore di \u00abadmintimeout\u00bb non interpretabile.",
	},
	"fos.intrazone.allowed": {
		"en": "{count} zones allow traffic between their own interfaces without going through a policy.",
		"it": "{count} zone consentono il traffico fra le proprie interfacce senza passare da una policy.",
	},
	"fos.intrazone.no_zones": {
		"en": "No zone defined: intra-zone traffic does not apply.",
		"it": "Nessuna zona definita: il traffico intra-zona non e' applicabile.",
	},
	"fos.intrazone.ok": {
		"en": "Every zone denies intra-zone traffic.",
		"it": "Tutte le zone negano il traffico intra-zona.",
	},
	"fos.local_in.empty": {
		"en": "\u00ablocal-in-policy\u00bb block present but empty.",
		"it": "Blocco \u00ablocal-in-policy\u00bb presente ma vuoto.",
	},
	"fos.local_in.no_section": {
		"en": "No \u00ablocal-in\u00bb policy: traffic aimed at the device itself is filtered only by \u00aballowaccess\u00bb, which does not discriminate by source.",
		"it": "Nessuna policy \u00ablocal-in\u00bb: il traffico diretto all'apparato e' filtrato solo da \u00aballowaccess\u00bb, che non distingue le sorgenti.",
	},
	"fos.local_in.ok": {
		"en": "{count} \u00ablocal-in\u00bb policies protecting the device's own services.",
		"it": "{count} policy \u00ablocal-in\u00bb a protezione dei servizi dell'apparato.",
	},
	"fos.lockout.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: account lockout cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare il blocco degli account.",
	},
	"fos.lockout.ok": {
		"en": "Account locked after {threshold} attempts for at least {duration} seconds.",
		"it": "Blocco account dopo {threshold} tentativi per almeno {duration} secondi.",
	},
	"fos.lockout.weak": {
		"en": "Administrative account lockout too permissive: it needs at most {threshold} attempts and at least {duration} seconds of lockout, otherwise brute forcing stays practical.",
		"it": "Blocco degli account amministrativi troppo permissivo: servono al massimo {threshold} tentativi e almeno {duration} secondi di blocco, altrimenti un attacco a forza bruta resta praticabile.",
	},
	"fos.log_disk.disabled": {
		"en": "Local disk logging disabled: if the remote collector is unreachable, nothing is retained.",
		"it": "Registrazione su disco locale disattivata: se il collector remoto e' irraggiungibile non resta alcuna traccia.",
	},
	"fos.log_disk.no_section": {
		"en": "\u00abconfig log disk setting\u00bb section absent: the device may have no local disk.",
		"it": "Sezione \u00abconfig log disk setting\u00bb assente: l'apparato potrebbe non avere un disco locale.",
	},
	"fos.log_disk.ok": {
		"en": "Local disk logging enabled.",
		"it": "Registrazione locale su disco attiva.",
	},
	"fos.mgmt_proto.insecure": {
		"en": "Unencrypted management protocols (Telnet/HTTP) enabled on {count} interface(s).",
		"it": "Protocolli di amministrazione non cifrati (Telnet/HTTP) abilitati su {count} interfaccia/e.",
	},
	"fos.mgmt_proto.no_section": {
		"en": "\u00abconfig system interface\u00bb section absent: management protocols cannot be assessed.",
		"it": "Sezione \u00abconfig system interface\u00bb assente: impossibile valutare i protocolli di gestione.",
	},
	"fos.mgmt_proto.ok": {
		"en": "Every interface allows encrypted management protocols only.",
		"it": "Tutte le interfacce usano solo protocolli di gestione cifrati.",
	},
	"fos.ntp.no_section": {
		"en": "No time synchronisation configured: the \u00abconfig system ntp\u00bb section does not exist.",
		"it": "Nessuna sincronizzazione oraria configurata: la sezione \u00abconfig system ntp\u00bb non esiste.",
	},
	"fos.ntp.not_syncing": {
		"en": "Time synchronisation not enabled, or with no source: logs cannot be correlated across devices.",
		"it": "Sincronizzazione oraria non attiva o priva di sorgente: i log non sono correlabili fra apparati.",
	},
	"fos.ntp.ok": {
		"en": "NTP synchronisation enabled ({count} servers declared).",
		"it": "Sincronizzazione NTP attiva ({count} server dichiarati).",
	},
	"fos.policy.no_section": {
		"en": "\u00abconfig firewall policy\u00bb section absent: access rules cannot be assessed.",
		"it": "Sezione \u00abconfig firewall policy\u00bb assente: impossibile valutare le regole di accesso.",
	},
	"fos.policy.no_wan": {
		"en": "No WAN interface identifiable: there is no way to tell which policies cross the perimeter.",
		"it": "Nessuna interfaccia WAN identificabile: impossibile stabilire quali policy attraversano il perimetro.",
	},
	"fos.policy_log.missing": {
		"en": "{count} policies accept traffic without logging it: that traffic appears in no later investigation.",
		"it": "{count} policy accettano traffico senza registrarlo: quel traffico non compare in nessuna indagine successiva.",
	},
	"fos.policy_log.ok": {
		"en": "Every policy that accepts traffic also logs it.",
		"it": "Tutte le policy che accettano traffico lo registrano.",
	},
	"fos.profiles.missing": {
		"en": "{count} policies route traffic to the Internet with no inspection profile: the device treats them as plain routing.",
		"it": "{count} policy instradano traffico verso Internet senza alcun profilo di ispezione: l'apparato le tratta come semplice routing.",
	},
	"fos.profiles.ok": {
		"en": "Every Internet-bound policy applies at least one inspection profile.",
		"it": "Ogni policy verso Internet applica almeno un profilo di ispezione.",
	},
	"fos.pwpolicy.no_section": {
		"en": "No password policy defined: the \u00abconfig system password-policy\u00bb section does not exist.",
		"it": "Nessuna policy password definita: la sezione \u00abconfig system password-policy\u00bb non esiste.",
	},
	"fos.pwpolicy.ok": {
		"en": "Password policy compliant: at least {minlen} characters with all four required classes.",
		"it": "Policy password conforme: almeno {minlen} caratteri con tutte e quattro le classi richieste.",
	},
	"fos.pwpolicy.weak": {
		"en": "Password policy below the minimum requirements ({count} parameters non-compliant): at least {minlen} characters and at least one character from each of the four classes.",
		"it": "Policy password sotto i requisiti minimi ({count} parametri non conformi): lunghezza minima {minlen} caratteri e almeno un carattere per ciascuna delle quattro classi.",
	},
	"fos.snmp_default.found": {
		"en": "Default cleartext SNMP communities (\u00abpublic\u00bb/\u00abprivate\u00bb): {count}.",
		"it": "Community SNMP di default in chiaro (\u00abpublic\u00bb/\u00abprivate\u00bb): {count}.",
	},
	"fos.snmp_default.no_section": {
		"en": "\u00abconfig system snmp community\u00bb section absent: SNMP communities cannot be assessed.",
		"it": "Sezione \u00abconfig system snmp community\u00bb assente: impossibile valutare le community SNMP.",
	},
	"fos.snmp_default.ok": {
		"en": "No default SNMP community configured.",
		"it": "Nessuna community SNMP di default configurata.",
	},
	"fos.snmpv3.no_snmp": {
		"en": "No SNMP configuration present: nothing to assess.",
		"it": "Nessuna configurazione SNMP presente: nulla da valutare.",
	},
	"fos.snmpv3.no_user": {
		"en": "No active v1/v2c community, but no SNMPv3 user either: SNMP monitoring is not configured.",
		"it": "Nessuna community v1/v2c attiva ma nemmeno un utente SNMPv3: il monitoraggio SNMP non e' configurato.",
	},
	"fos.snmpv3.ok": {
		"en": "SNMPv3 only.",
		"it": "Solo SNMPv3 in uso.",
	},
	"fos.snmpv3.v1v2c": {
		"en": "{count} SNMP v1/v2c communities active: the community travels in cleartext and counts as a credential.",
		"it": "{count} community SNMP v1/v2c attive: la community viaggia in chiaro e vale come credenziale.",
	},
	"fos.sslvpn.no_section": {
		"en": "\u00abconfig vpn ssl settings\u00bb section absent: SSL-VPN not configured.",
		"it": "Sezione \u00abconfig vpn ssl settings\u00bb assente: SSL-VPN non configurata.",
	},
	"fos.sslvpn_src.any": {
		"en": "SSL-VPN portal exposed to \u00aball\u00bb: the source restriction exists but does nothing.",
		"it": "Portale SSL-VPN esposto a \u00aball\u00bb: restrizione sorgente presente ma inefficace.",
	},
	"fos.sslvpn_src.ok": {
		"en": "SSL-VPN portal access restricted by source address.",
		"it": "Accesso al portale SSL-VPN ristretto per indirizzo sorgente.",
	},
	"fos.sslvpn_src.unrestricted": {
		"en": "SSL-VPN portal reachable from any address: without \u00absource-address\u00bb the only barrier is the credentials.",
		"it": "Portale SSL-VPN raggiungibile da qualunque indirizzo: senza \u00absource-address\u00bb l'unica barriera sono le credenziali.",
	},
	"fos.sslvpn_tls.not_set": {
		"en": "Minimum TLS version for the SSL-VPN not set: the platform default applies.",
		"it": "Versione TLS minima della SSL-VPN non impostata: vale il default della piattaforma.",
	},
	"fos.sslvpn_tls.ok": {
		"en": "SSL-VPN restricted to TLS 1.2 or above.",
		"it": "SSL-VPN limitata a TLS 1.2 o superiore.",
	},
	"fos.sslvpn_tls.weak": {
		"en": "The SSL-VPN accepts deprecated TLS (\u00ab{version}\u00bb).",
		"it": "SSL-VPN accetta TLS deprecato (\u00ab{version}\u00bb).",
	},
	"fos.static_ciphers.bad": {
		"en": "Static-key ciphers accepted: without forward secrecy, anyone who obtains the server key can decrypt traffic captured in the past.",
		"it": "Cifrari a chiave statica ammessi: senza forward secrecy, chi compromette la chiave del server puo' decifrare il traffico registrato in passato.",
	},
	"fos.static_ciphers.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: static-key ciphers cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare i cifrari a chiave statica.",
	},
	"fos.static_ciphers.not_set": {
		"en": "\u00abssl-static-key-ciphers\u00bb not set: the platform default applies.",
		"it": "\u00abssl-static-key-ciphers\u00bb non impostato: vale il default della piattaforma.",
	},
	"fos.static_ciphers.ok": {
		"en": "Static-key ciphers disabled.",
		"it": "Cifrari a chiave statica disabilitati.",
	},
	"fos.strong_crypto.bad": {
		"en": "\u00abstrong-crypto\u00bb disabled: weak ciphers accepted.",
		"it": "\u00abstrong-crypto\u00bb disabilitato: cifrari deboli ammessi.",
	},
	"fos.strong_crypto.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: \u00abstrong-crypto\u00bb cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare \u00abstrong-crypto\u00bb.",
	},
	"fos.strong_crypto.not_set": {
		"en": "\u00abstrong-crypto\u00bb not set: weak ciphers may be accepted.",
		"it": "\u00abstrong-crypto\u00bb non impostato: cifrari deboli potenzialmente ammessi.",
	},
	"fos.strong_crypto.ok": {
		"en": "\u00abstrong-crypto\u00bb enabled.",
		"it": "\u00abstrong-crypto\u00bb abilitato.",
	},
	"fos.syslog.incomplete": {
		"en": "Remote syslog forwarding not enabled, or with no destination.",
		"it": "Inoltro syslog remoto non attivo o privo di destinazione.",
	},
	"fos.syslog.no_section": {
		"en": "No remote syslog forwarding configured: the \u00abconfig log syslogd setting\u00bb section does not exist.",
		"it": "Nessun inoltro syslog remoto configurato: la sezione \u00abconfig log syslogd setting\u00bb non esiste.",
	},
	"fos.syslog.ok": {
		"en": "Log forwarding to a remote syslog collector enabled and configured.",
		"it": "Inoltro dei log verso syslog remoto attivo e configurato.",
	},
	"fos.syslog_enc.disabled": {
		"en": "Syslog forwarding not enabled: transport encryption does not apply.",
		"it": "Inoltro syslog non attivo: la cifratura del trasporto non e' applicabile.",
	},
	"fos.syslog_enc.no_syslog": {
		"en": "No remote syslog configured: transport encryption does not apply.",
		"it": "Nessun syslog remoto configurato: la cifratura del trasporto non e' applicabile.",
	},
	"fos.syslog_enc.ok": {
		"en": "Syslog forwarding encrypted (\u00abenc-algorithm {algorithm}\u00bb).",
		"it": "Inoltro syslog cifrato (\u00abenc-algorithm {algorithm}\u00bb).",
	},
	"fos.syslog_enc.plaintext": {
		"en": "Logs sent to the remote syslog in cleartext: anyone tapping the segment reads the addresses, users and destinations of every session.",
		"it": "Log inviati al syslog remoto in chiaro: chi intercetta il segmento legge indirizzi, utenti e destinazioni di ogni sessione.",
	},
	"fos.timezone.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the time zone cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare il fuso orario.",
	},
	"fos.timezone.not_set": {
		"en": "Time zone not set: log timestamps use the factory default and do not match local time.",
		"it": "Fuso orario non impostato: i timestamp dei log usano il default di fabbrica e non corrispondono all'ora locale.",
	},
	"fos.timezone.ok": {
		"en": "Time zone set explicitly.",
		"it": "Fuso orario impostato esplicitamente.",
	},
	"fos.tls.no_section": {
		"en": "\u00abconfig system global\u00bb section absent: the minimum TLS version cannot be assessed.",
		"it": "Sezione \u00abconfig system global\u00bb assente: impossibile valutare la versione minima TLS.",
	},
	"fos.tls.not_set": {
		"en": "Minimum TLS version not set explicitly: the platform default applies, and it changes between FortiOS releases.",
		"it": "Versione minima TLS non impostata esplicitamente: si applica il default della piattaforma, che varia con la versione di FortiOS.",
	},
	"fos.tls.ok": {
		"en": "Minimum SSL/TLS version compliant (TLS 1.2+).",
		"it": "Versione minima SSL/TLS conforme (TLS 1.2+).",
	},
	"fos.tls.weak": {
		"en": "Deprecated TLS version allowed: {versions}.",
		"it": "Versione TLS deprecata ammessa: {versions}.",
	},
	"fos.trusthost.no_section": {
		"en": "\u00abconfig system admin\u00bb section absent: administrative access restrictions cannot be assessed.",
		"it": "Sezione \u00abconfig system admin\u00bb assente: impossibile valutare le restrizioni di accesso amministrativo.",
	},
	"fos.trusthost.ok": {
		"en": "Every administrative account is restricted to trusted management subnets.",
		"it": "Tutti gli account amministrativi sono ristretti a sottoreti di gestione fidate.",
	},
	"fos.trusthost.unrestricted": {
		"en": "{count} administrative accounts reachable from any source IP.",
		"it": "{count} account amministrativi accessibili da qualunque IP sorgente.",
	},
	"ios.aaa.absent": {
		"en": "\u00abaaa new-model\u00bb absent: the device falls back to legacy line authentication.",
		"it": "\u00abaaa new-model\u00bb assente: l'apparato usa l'autenticazione legacy di linea.",
	},
	"ios.aaa.disabled": {
		"en": "\u00abaaa new-model\u00bb explicitly disabled: no centralised access control.",
		"it": "\u00abaaa new-model\u00bb esplicitamente disabilitato: nessun controllo accessi centralizzato.",
	},
	"ios.aaa.not_applicable_accounting": {
		"en": "\u00abaaa new-model\u00bb not enabled: AAA accounting does not apply.",
		"it": "\u00abaaa new-model\u00bb non attivo: l'accounting AAA non e' applicabile.",
	},
	"ios.aaa.not_applicable_login": {
		"en": "\u00abaaa new-model\u00bb not enabled: AAA login methods do not apply.",
		"it": "\u00abaaa new-model\u00bb non attivo: i metodi AAA di login non sono applicabili.",
	},
	"ios.aaa.ok": {
		"en": "\u00abaaa new-model\u00bb enabled.",
		"it": "\u00abaaa new-model\u00bb abilitato.",
	},
	"ios.aaa_login.absent": {
		"en": "No \u00abaaa authentication login\u00bb defined.",
		"it": "Nessun \u00abaaa authentication login\u00bb definito.",
	},
	"ios.aaa_login.none": {
		"en": "Login method with a \u00abnone\u00bb fallback: access with no credentials.",
		"it": "Metodo di login con fallback \u00abnone\u00bb: accesso senza credenziali.",
	},
	"ios.aaa_login.ok": {
		"en": "AAA login authentication defined ({count} lists).",
		"it": "Autenticazione di login AAA definita ({count} liste).",
	},
	"ios.accounting.absent": {
		"en": "No \u00abaaa accounting commands 15\u00bb: privileged commands leave no record of who ran them.",
		"it": "Nessun \u00abaaa accounting commands 15\u00bb: i comandi privilegiati non lasciano traccia di chi li ha eseguiti.",
	},
	"ios.accounting.ok": {
		"en": "Accounting of privileged (level 15) commands enabled.",
		"it": "Accounting dei comandi privilegiati (livello 15) attivo.",
	},
	"ios.aux.absent": {
		"en": "No \u00abline aux\u00bb present: the device exposes no auxiliary port.",
		"it": "Nessuna \u00abline aux\u00bb presente: l'apparato non espone una porta ausiliaria.",
	},
	"ios.aux.exec_active": {
		"en": "EXEC process active on the auxiliary port.",
		"it": "Processo EXEC attivo sulla porta ausiliaria.",
	},
	"ios.aux.ok": {
		"en": "EXEC process disabled on the auxiliary port.",
		"it": "Processo EXEC disabilitato sulla porta ausiliaria.",
	},
	"ios.banner.absent": {
		"en": "\u00ab{kind}\u00bb banner absent: no legal notice on access.",
		"it": "Banner \u00ab{kind}\u00bb assente: nessuna avvertenza legale all'accesso.",
	},
	"ios.banner.ok": {
		"en": "\u00ab{kind}\u00bb banner configured.",
		"it": "Banner \u00ab{kind}\u00bb configurato.",
	},
	"ios.cdp.enabled": {
		"en": "CDP enabled: it announces the model, IOS version and identity of the device to anyone on the segment.",
		"it": "CDP attivo: annuncia modello, versione IOS e identita' dell'apparato a chiunque sia sul segmento.",
	},
	"ios.con_timeout.absent": {
		"en": "No \u00abline con\u00bb configured.",
		"it": "Nessuna \u00abline con\u00bb configurata.",
	},
	"ios.con_timeout.bad": {
		"en": "Idle timeout missing, disabled or above {max} minutes on {count} console lines.",
		"it": "Timeout di inattivita' assente, disabilitato o superiore a {max} minuti su {count} linee console.",
	},
	"ios.con_timeout.ok": {
		"en": "Idle timeout within {max} minutes on every console line.",
		"it": "Timeout di inattivita' entro {max} minuti su tutte le linee console.",
	},
	"ios.dhcp.enabled": {
		"en": "DHCP service running on the network device: pointless attack surface when addressing is served elsewhere.",
		"it": "Servizio DHCP attivo sull'apparato di rete: superficie di attacco inutile se l'indirizzamento e' erogato altrove.",
	},
	"ios.domain.absent": {
		"en": "\u00abip domain-name\u00bb absent: without a domain the RSA key pair for SSH cannot be generated.",
		"it": "\u00abip domain-name\u00bb assente: senza dominio non e' possibile generare la coppia di chiavi RSA per SSH.",
	},
	"ios.domain.ok": {
		"en": "Domain configured: {domain}.",
		"it": "Dominio configurato: {domain}.",
	},
	"ios.empty": {
		"en": "Configuration empty, or not recognised as Cisco IOS.",
		"it": "Configurazione vuota o non riconosciuta come Cisco IOS.",
	},
	"ios.enable.absent": {
		"en": "No \u00abenable secret\u00bb: privileged access is not password protected.",
		"it": "Nessun \u00abenable secret\u00bb: l'accesso privilegiato non e' protetto da password.",
	},
	"ios.enable.ok": {
		"en": "\u00abenable secret\u00bb configured.",
		"it": "\u00abenable secret\u00bb configurato.",
	},
	"ios.enable.password": {
		"en": "\u00abenable password\u00bb in use: reversible type-7 encoding.",
		"it": "\u00abenable password\u00bb in uso: cifratura reversibile di tipo 7.",
	},
	"ios.keepalive.missing": {
		"en": "TCP keepalives missing ({directives}): dropped sessions stay open and can be hijacked.",
		"it": "Keepalive TCP mancanti ({directives}): le sessioni interrotte restano aperte e sono dirottabili.",
	},
	"ios.keepalive.ok": {
		"en": "TCP keepalives enabled inbound and outbound.",
		"it": "Keepalive TCP attivi in ingresso e in uscita.",
	},
	"ios.log_buffer.absent": {
		"en": "No \u00ablogging buffered\u00bb: with no local buffer the device keeps nothing you can read back.",
		"it": "Nessun \u00ablogging buffered\u00bb: senza buffer locale non resta traccia consultabile dall'apparato.",
	},
	"ios.log_buffer.no_size": {
		"en": "\u00ablogging buffered\u00bb with no explicit size: the platform default applies.",
		"it": "\u00ablogging buffered\u00bb senza dimensione esplicita: vale il default di piattaforma.",
	},
	"ios.log_buffer.ok": {
		"en": "Log buffer of {size} bytes.",
		"it": "Buffer di log di {size} byte.",
	},
	"ios.log_buffer.small": {
		"en": "Log buffer small ({size} bytes, recommended {min}): older events get overwritten quickly.",
		"it": "Buffer di log piccolo ({size} byte, consigliato {min}): gli eventi piu' vecchi vengono sovrascritti in fretta.",
	},
	"ios.log_console.not_set": {
		"en": "\u00ablogging console\u00bb not limited: the default sends EVERY message to the console, which is slow and drops them under load.",
		"it": "\u00ablogging console\u00bb non limitato: il default invia OGNI messaggio alla console, che e' lenta e li perde in caso di picco.",
	},
	"ios.log_console.ok": {
		"en": "Console logging limited to \u00ab{level}\u00bb.",
		"it": "Log su console limitati a \u00ab{level}\u00bb.",
	},
	"ios.log_console.verbose": {
		"en": "Console log level too verbose (\u00ab{level}\u00bb): under load the queue fills and messages are discarded.",
		"it": "Livello di log su console troppo verboso (\u00ab{level}\u00bb): in caso di picco la coda si riempie e i messaggi vengono scartati.",
	},
	"ios.log_host.absent": {
		"en": "No \u00ablogging host\u00bb: logs stay on the device only and are lost at reboot.",
		"it": "Nessun \u00ablogging host\u00bb: i log restano solo sull'apparato e si perdono al riavvio.",
	},
	"ios.log_host.ok": {
		"en": "Log forwarding to {count} remote collector(s).",
		"it": "Inoltro dei log verso {count} collector remoto/i.",
	},
	"ios.log_source.absent": {
		"en": "No \u00ablogging source-interface\u00bb: the source IP of the messages changes with the route, complicating filters and correlation.",
		"it": "Nessuna \u00ablogging source-interface\u00bb: l'IP sorgente dei messaggi cambia con la rotta e complica filtri e correlazione.",
	},
	"ios.log_source.ok": {
		"en": "Log source interface pinned.",
		"it": "Interfaccia sorgente dei log fissata.",
	},
	"ios.log_trap.not_set": {
		"en": "\u00ablogging trap\u00bb not set: the severity sent to the remote syslog stays at its default.",
		"it": "\u00ablogging trap\u00bb non impostato: la severita' inviata al syslog remoto resta quella di default.",
	},
	"ios.log_trap.ok": {
		"en": "Severity towards the remote syslog at \u00ab{level}\u00bb.",
		"it": "Severita' verso syslog remoto a \u00ab{level}\u00bb.",
	},
	"ios.log_trap.too_strict": {
		"en": "Severity towards the remote syslog too restrictive (\u00ab{level}\u00bb): informational events are not forwarded.",
		"it": "Severita' verso syslog remoto troppo restrittiva (\u00ab{level}\u00bb): gli eventi informativi non vengono inoltrati.",
	},
	"ios.login_log.missing": {
		"en": "Logins not recorded ({directives}): there is no way to reconstruct who logged in and when.",
		"it": "Accessi non registrati ({directives}): impossibile ricostruire chi e' entrato e quando.",
	},
	"ios.login_log.ok": {
		"en": "Both successful and failed logins recorded.",
		"it": "Accessi riusciti e falliti registrati entrambi.",
	},
	"ios.ntp.absent": {
		"en": "No \u00abntp server\u00bb: without a synchronised clock, logs and certificate validity cannot be trusted.",
		"it": "Nessun \u00abntp server\u00bb: senza orologio sincronizzato i log e la validita' dei certificati non sono affidabili.",
	},
	"ios.ntp.ok": {
		"en": "{count} NTP servers configured.",
		"it": "{count} server NTP configurati.",
	},
	"ios.ntp.single": {
		"en": "Only one NTP server configured: no redundancy if the time source fails.",
		"it": "Un solo server NTP configurato: nessuna ridondanza in caso di guasto della sorgente oraria.",
	},
	"ios.ntp_auth.missing": {
		"en": "NTP not authenticated: the device takes the time from any source claiming to be a server.",
		"it": "NTP non autenticato: l'apparato accetta l'ora da qualunque sorgente che si dichiari server.",
	},
	"ios.ntp_auth.not_applicable": {
		"en": "No NTP server configured: NTP authentication does not apply.",
		"it": "Nessun server NTP configurato: autenticazione NTP non applicabile.",
	},
	"ios.ntp_auth.ok": {
		"en": "NTP authenticated with a trusted key.",
		"it": "NTP autenticato con chiave fidata.",
	},
	"ios.pad.enabled": {
		"en": "PAD (X.25) service running: it exposes the PAD command set.",
		"it": "Servizio PAD (X.25) attivo: espone il set di comandi PAD.",
	},
	"ios.proxy_arp.enabled": {
		"en": "Proxy ARP not disabled on {count} interface(s): it extends the broadcast domain past the segment and weakens segmentation.",
		"it": "Proxy ARP non disabilitato su {count} interfaccia/e: estende il dominio di broadcast oltre il segmento e indebolisce la segmentazione.",
	},
	"ios.proxy_arp.no_ip_iface": {
		"en": "No interface with an IP address: proxy ARP cannot be assessed.",
		"it": "Nessuna interfaccia con indirizzo IP: proxy ARP non valutabile.",
	},
	"ios.proxy_arp.ok": {
		"en": "Proxy ARP disabled on every addressed interface.",
		"it": "Proxy ARP disabilitato su tutte le interfacce indirizzate.",
	},
	"ios.pw_encryption.absent": {
		"en": "\u00abservice password-encryption\u00bb absent: line passwords stay in cleartext.",
		"it": "\u00abservice password-encryption\u00bb assente: le password di linea restano in chiaro.",
	},
	"ios.pw_encryption.disabled": {
		"en": "\u00abservice password-encryption\u00bb explicitly disabled: cleartext passwords in the configuration.",
		"it": "\u00abservice password-encryption\u00bb esplicitamente disabilitato: password in chiaro nella configurazione.",
	},
	"ios.pw_encryption.ok": {
		"en": "\u00abservice password-encryption\u00bb enabled.",
		"it": "\u00abservice password-encryption\u00bb abilitato.",
	},
	"ios.service.not_disabled": {
		"en": "No \u00abno {service}\u00bb in the configuration: the service stays at its factory default (on) and is not explicitly disabled.",
		"it": "Nessun \u00abno {service}\u00bb in configurazione: il servizio resta al default di fabbrica (attivo) e non e' disattivato esplicitamente.",
	},
	"ios.service.ok": {
		"en": "\u00ab{service}\u00bb disabled.",
		"it": "\u00ab{service}\u00bb disabilitato.",
	},
	"ios.snmp.absent": {
		"en": "No SNMP community configured: nothing to assess.",
		"it": "Nessuna community SNMP configurata: nulla da valutare.",
	},
	"ios.snmp_acl.missing": {
		"en": "{count} SNMP communities queryable from any host: the access-list is missing.",
		"it": "{count} community SNMP interrogabili da qualunque host: manca la access-list.",
	},
	"ios.snmp_acl.ok": {
		"en": "Every SNMP community is restricted by an access-list.",
		"it": "Ogni community SNMP e' ristretta da una access-list.",
	},
	"ios.snmp_default.found": {
		"en": "Default SNMP communities (\u00abpublic\u00bb/\u00abprivate\u00bb) in use: {count}.",
		"it": "Community SNMP di default (\u00abpublic\u00bb/\u00abprivate\u00bb) in uso: {count}.",
	},
	"ios.snmp_default.ok": {
		"en": "No default SNMP community.",
		"it": "Nessuna community SNMP di default.",
	},
	"ios.snmp_rw.found": {
		"en": "Read-write SNMP communities: they allow reconfiguring the device over SNMP ({count}).",
		"it": "Community SNMP in scrittura: consentono di riconfigurare l'apparato via SNMP ({count}).",
	},
	"ios.snmp_rw.ok": {
		"en": "No read-write SNMP community.",
		"it": "Nessuna community SNMP in scrittura.",
	},
	"ios.snmpv3.absent": {
		"en": "No SNMPv3 group or user configured.",
		"it": "Nessun gruppo o utente SNMPv3 configurato.",
	},
	"ios.snmpv3.ok": {
		"en": "SNMPv3 configured with authentication and AES-{bits} encryption or better.",
		"it": "SNMPv3 configurato con autenticazione e cifratura AES-{bits} o superiore.",
	},
	"ios.snmpv3.weak": {
		"en": "SNMPv3 without encryption, or below AES-{bits} ({count} findings).",
		"it": "SNMPv3 senza cifratura o con cifratura sotto AES-{bits} ({count} riscontri).",
	},
	"ios.source_route.enabled": {
		"en": "Source routing enabled: it lets the sender dictate the packet path, a technique used to bypass routing controls.",
		"it": "Source routing attivo: consente al mittente di imporre il percorso dei pacchetti, tecnica usata per aggirare i controlli di rotta.",
	},
	"ios.ssh_retries.not_set": {
		"en": "\u00abip ssh authentication-retries\u00bb not set: the platform default applies (3).",
		"it": "\u00abip ssh authentication-retries\u00bb non impostato: vale il default di piattaforma (3).",
	},
	"ios.ssh_retries.ok": {
		"en": "SSH authentication attempts limited to {value}.",
		"it": "Tentativi di autenticazione SSH limitati a {value}.",
	},
	"ios.ssh_retries.too_high": {
		"en": "Too many authentication attempts per SSH session ({value}, recommended maximum {max}).",
		"it": "Troppi tentativi di autenticazione per sessione SSH ({value}, massimo consigliato {max}).",
	},
	"ios.ssh_retries.unreadable": {
		"en": "\u00abip ssh authentication-retries\u00bb value cannot be read as a number.",
		"it": "Valore di \u00abip ssh authentication-retries\u00bb non interpretabile.",
	},
	"ios.ssh_timeout.not_set": {
		"en": "\u00abip ssh time-out\u00bb not set: the platform default applies (120 s).",
		"it": "\u00abip ssh time-out\u00bb non impostato: vale il default di piattaforma (120 s).",
	},
	"ios.ssh_timeout.ok": {
		"en": "SSH login timeout at {value} seconds.",
		"it": "Timeout di login SSH a {value} secondi.",
	},
	"ios.ssh_timeout.too_high": {
		"en": "SSH login timeout too high ({value} s, recommended maximum {max}).",
		"it": "Timeout di login SSH troppo alto ({value} s, massimo consigliato {max}).",
	},
	"ios.ssh_timeout.unreadable": {
		"en": "\u00abip ssh time-out\u00bb value cannot be read as a number.",
		"it": "Valore di \u00abip ssh time-out\u00bb non interpretabile.",
	},
	"ios.ssh_version.not_set": {
		"en": "\u00abip ssh version\u00bb not set: SSH runs in compatibility mode and accepts version 1 as well.",
		"it": "\u00abip ssh version\u00bb non impostato: SSH opera in modalita' compatibile e accetta anche la versione 1.",
	},
	"ios.ssh_version.ok": {
		"en": "SSH forced to version 2.",
		"it": "SSH forzato alla versione 2.",
	},
	"ios.ssh_version.v1": {
		"en": "SSH version 1 allowed: a protocol with known vulnerabilities.",
		"it": "SSH versione 1 ammessa: protocollo con vulnerabilita' note.",
	},
	"ios.timestamps.absent": {
		"en": "No \u00abservice timestamps\u00bb: messages cannot be correlated with those from other devices.",
		"it": "Nessun \u00abservice timestamps\u00bb: i messaggi non sono correlabili con quelli degli altri apparati.",
	},
	"ios.timestamps.ok": {
		"en": "Date and time stamps on logs and debugs.",
		"it": "Timestamp con data e ora su log e debug.",
	},
	"ios.timestamps.uptime": {
		"en": "Timestamps based on uptime rather than wall-clock time: useless for correlating across devices.",
		"it": "Timestamp basati sull'uptime invece che sulla data: inutilizzabili per correlare tra apparati.",
	},
	"ios.tunnel.none": {
		"en": "No tunnel interface configured.",
		"it": "Nessuna interfaccia tunnel configurata.",
	},
	"ios.tunnel.present": {
		"en": "{count} tunnel interfaces present: confirm they are intended \u2014 they are an egress path that bypasses perimeter controls.",
		"it": "{count} interfacce tunnel presenti: da confermare come previste, sono un canale di uscita che aggira i controlli perimetrali.",
	},
	"ios.user_priv.high": {
		"en": "{count} local users with \u00abprivilege 15\u00bb: they get privileged EXEC without going through \u00abenable\u00bb.",
		"it": "{count} utenti locali con \u00abprivilege 15\u00bb: ottengono EXEC privilegiato senza passare da \u00abenable\u00bb.",
	},
	"ios.user_priv.ok": {
		"en": "No local user with direct privilege 15.",
		"it": "Nessun utente locale con privilegio 15 diretto.",
	},
	"ios.user_secret.ok": {
		"en": "Every local user uses \u00absecret\u00bb.",
		"it": "Tutti gli utenti locali usano \u00absecret\u00bb.",
	},
	"ios.user_secret.password": {
		"en": "{count} local users using \u00abpassword\u00bb instead of \u00absecret\u00bb: reversible or weak hash.",
		"it": "{count} utenti locali con \u00abpassword\u00bb invece di \u00absecret\u00bb: hash reversibile o debole.",
	},
	"ios.users.absent": {
		"en": "No local user defined.",
		"it": "Nessun utente locale definito.",
	},
	"ios.vty.absent": {
		"en": "No \u00abline vty\u00bb configured: remote access cannot be assessed.",
		"it": "Nessuna \u00abline vty\u00bb configurata: accesso remoto non valutabile.",
	},
	"ios.vty_acl.missing": {
		"en": "{count} vty line(s) reachable from any source address.",
		"it": "{count} linea/e vty raggiungibili da qualunque indirizzo sorgente.",
	},
	"ios.vty_acl.ok": {
		"en": "Every \u00abline vty\u00bb is restricted by an access-class.",
		"it": "Ogni \u00abline vty\u00bb e' ristretta da una access-class.",
	},
	"ios.vty_timeout.absent": {
		"en": "No \u00abline vty\u00bb configured.",
		"it": "Nessuna \u00abline vty\u00bb configurata.",
	},
	"ios.vty_timeout.bad": {
		"en": "Idle timeout missing, disabled or above {max} minutes on {count} vty lines.",
		"it": "Timeout di inattivita' assente, disabilitato o superiore a {max} minuti su {count} linee vty.",
	},
	"ios.vty_timeout.ok": {
		"en": "Idle timeout within {max} minutes on every vty line.",
		"it": "Timeout di inattivita' entro {max} minuti su tutte le linee vty.",
	},
	"ios.vty_transport.insecure": {
		"en": "Unencrypted protocols allowed on {count} vty line(s).",
		"it": "Protocolli non cifrati ammessi su {count} linea/e vty.",
	},
	"ios.vty_transport.ok": {
		"en": "Every \u00abline vty\u00bb accepts SSH only.",
		"it": "Tutte le \u00abline vty\u00bb accettano solo SSH.",
	},
	"lnx.empty": {
		"en": "Empty or unreadable artifact: there is nothing to assess.",
		"it": "Artefatto vuoto o illeggibile: non c'e' nulla da valutare.",
	},
	"lnx.encrypt.ok": {
		"en": "Password hashing uses \u00ab{value}\u00bb.",
		"it": "Hashing delle password con \u00ab{value}\u00bb.",
	},
	"lnx.encrypt.undeclared": {
		"en": "\u00abENCRYPT_METHOD\u00bb not declared in login.defs: the distribution default applies, and that is not guaranteed to stay the same.",
		"it": "\u00abENCRYPT_METHOD\u00bb non dichiarato in login.defs: vale il default della distribuzione, che non e' garantito nel tempo.",
	},
	"lnx.encrypt.weak": {
		"en": "Password hashing uses \u00ab{value}\u00bb: a fast algorithm makes brute force practical against a stolen \u00ab/etc/shadow\u00bb.",
		"it": "Hashing delle password con \u00ab{value}\u00bb: un algoritmo veloce rende praticabile la ricerca esaustiva su uno \u00ab/etc/shadow\u00bb rubato.",
	},
	"lnx.fstab.absent": {
		"en": "\u00ab/etc/fstab\u00bb missing from the backup: mount options cannot be assessed.",
		"it": "\u00ab/etc/fstab\u00bb assente dal backup: opzioni di mount non valutabili.",
	},
	"lnx.login_defs.absent": {
		"en": "\u00ab/etc/login.defs\u00bb missing from the backup: the password policy cannot be assessed.",
		"it": "\u00ab/etc/login.defs\u00bb assente dal backup: politica delle password non valutabile.",
	},
	"lnx.mount.missing_options": {
		"en": "\u00ab{mount}\u00bb mounted without \u00ab{missing}\u00bb: a world-writable directory can then host executables or setuid files.",
		"it": "\u00ab{mount}\u00bb montato senza \u00ab{missing}\u00bb: una directory scrivibile da tutti puo' ospitare eseguibili o file setuid.",
	},
	"lnx.mount.not_separate": {
		"en": "No fstab entry for \u00ab{mount}\u00bb: it is not a separate partition, or it is mounted elsewhere (e.g. a systemd tmpfs). The effective options are not visible from fstab.",
		"it": "Nessuna riga in fstab per \u00ab{mount}\u00bb: non e' una partizione separata, oppure e' montata altrove (es. tmpfs da systemd). Le opzioni effettive non si vedono da fstab.",
	},
	"lnx.mount.ok": {
		"en": "\u00ab{mount}\u00bb is mounted with the recommended restriction options.",
		"it": "\u00ab{mount}\u00bb montato con le opzioni di restrizione raccomandate.",
	},
	"lnx.pass_max.ok": {
		"en": "Password expires after {value} days.",
		"it": "Scadenza della password a {value} giorni.",
	},
	"lnx.pass_max.too_long": {
		"en": "Password expires after {value} days (recommended maximum {limit}; 0 or missing means it never expires).",
		"it": "Scadenza della password a {value} giorni (massimo raccomandato {limit}; 0 o assente significa nessuna scadenza).",
	},
	"lnx.pass_min.ok": {
		"en": "Minimum interval between password changes: {value} days.",
		"it": "Intervallo minimo fra due cambi password: {value} giorni.",
	},
	"lnx.pass_min.too_short": {
		"en": "Minimum interval between password changes of {value} days (recommended minimum {limit}): with no wait a user can cycle through the history and return to the old password.",
		"it": "Intervallo minimo fra due cambi password di {value} giorni (minimo raccomandato {limit}): senza attesa, un utente puo' aggirare lo storico ricambiando la password piu' volte di fila.",
	},
	"lnx.pass_policy.undeclared": {
		"en": "\u00ab{what}\u00bb not declared in login.defs: no policy for this parameter.",
		"it": "\u00ab{what}\u00bb non dichiarato in login.defs: nessuna politica per questo parametro.",
	},
	"lnx.pass_policy.unreadable": {
		"en": "\u00ab{what}\u00bb present but with a non-numeric value.",
		"it": "\u00ab{what}\u00bb presente ma con un valore non numerico.",
	},
	"lnx.pass_warn.ok": {
		"en": "Expiry warning: {value} days.",
		"it": "Preavviso di scadenza: {value} giorni.",
	},
	"lnx.pass_warn.too_short": {
		"en": "Expiry warning of {value} days (recommended minimum {limit}).",
		"it": "Preavviso di scadenza di {value} giorni (minimo raccomandato {limit}).",
	},
	"lnx.sshd.not_assessable": {
		"en": "\u00ab{what}\u00bb does not appear in sshd_config, which however includes \u00absshd_config.d/\u00bb: the effective setting is not in the backup. A triage with the sudo password collects \u00absshd -T\u00bb.",
		"it": "\u00ab{what}\u00bb non compare in sshd_config, che pero' include \u00absshd_config.d/\u00bb: l'impostazione effettiva non e' nel backup. Serve un triage con password sudo, che raccoglie \u00absshd -T\u00bb.",
	},
	"lnx.sshd_alive.disabled": {
		"en": "The server never closes idle sessions (interval {interval}, count {count}): an abandoned session stays open until the network drops it.",
		"it": "Il server non chiude le sessioni inattive (intervallo {interval}, conteggio {count}): una sessione abbandonata resta aperta finche' non cade la rete.",
	},
	"lnx.sshd_alive.ok": {
		"en": "Idle sessions are closed by the server (interval {interval}s, {count} probes).",
		"it": "Sessione inattiva chiusa dal server (intervallo {interval}s, {count} tentativi).",
	},
	"lnx.sshd_authtries.high": {
		"en": "{value} authentication attempts per connection (recommended maximum {max}).",
		"it": "{value} tentativi di autenticazione per connessione (massimo raccomandato {max}).",
	},
	"lnx.sshd_authtries.ok": {
		"en": "Authentication attempts per connection limited to {value}.",
		"it": "Tentativi di autenticazione per connessione limitati a {value}.",
	},
	"lnx.sshd_authtries.unreadable": {
		"en": "\u00abMaxAuthTries\u00bb present but with a non-numeric value.",
		"it": "\u00abMaxAuthTries\u00bb presente ma con un valore non numerico.",
	},
	"lnx.sshd_banner.absent": {
		"en": "No pre-authentication banner: the notice that access is restricted and monitored is missing.",
		"it": "Nessun avviso pre-autenticazione: manca la dichiarazione che l'accesso e' riservato e monitorato.",
	},
	"lnx.sshd_banner.ok": {
		"en": "Pre-authentication banner configured (\u00ab{value}\u00bb).",
		"it": "Avviso pre-autenticazione configurato (\u00ab{value}\u00bb).",
	},
	"lnx.sshd_empty.allowed": {
		"en": "SSH access with an empty password is allowed (\u00ab{value}\u00bb).",
		"it": "Accesso SSH con password vuota ammesso (\u00ab{value}\u00bb).",
	},
	"lnx.sshd_empty.ok": {
		"en": "No SSH access with an empty password.",
		"it": "Nessun accesso SSH con password vuota.",
	},
	"lnx.sshd_forwarding.allowed": {
		"en": "TCP/X11 forwarding allowed (\u00ab{value}\u00bb): the session can be used as a tunnel into networks the host reaches and the client does not.",
		"it": "Inoltro TCP/X11 consentito (\u00ab{value}\u00bb): la sessione puo' essere usata come tunnel verso reti che l'host raggiunge e il client no.",
	},
	"lnx.sshd_forwarding.ok": {
		"en": "TCP/X11 forwarding through the SSH session is disabled.",
		"it": "Inoltro TCP/X11 attraverso la sessione SSH disattivato.",
	},
	"lnx.sshd_grace.high": {
		"en": "Authentication window of {value} seconds (recommended maximum {max}; 0 means no limit at all).",
		"it": "Finestra di autenticazione di {value} secondi (massimo raccomandato {max}; 0 significa nessun limite).",
	},
	"lnx.sshd_grace.ok": {
		"en": "Authentication window of {value} seconds.",
		"it": "Finestra di autenticazione di {value} secondi.",
	},
	"lnx.sshd_grace.unreadable": {
		"en": "\u00abLoginGraceTime\u00bb present but with a non-numeric value.",
		"it": "\u00abLoginGraceTime\u00bb presente ma con un valore non numerico.",
	},
	"lnx.sshd_hostbased.enabled": {
		"en": "Host-based authentication enabled (\u00ab{value}\u00bb): trust moves from the individual account to the originating machine.",
		"it": "Autenticazione basata sull'host attiva (\u00ab{value}\u00bb): la fiducia si sposta dal singolo account alla macchina di origine.",
	},
	"lnx.sshd_hostbased.ok": {
		"en": "Host-based authentication is disabled.",
		"it": "Autenticazione basata sull'host disabilitata.",
	},
	"lnx.sshd_loglevel.ok": {
		"en": "SSH log level is adequate (\u00ab{value}\u00bb).",
		"it": "Livello di log SSH adeguato (\u00ab{value}\u00bb).",
	},
	"lnx.sshd_loglevel.weak": {
		"en": "SSH log level \u00ab{value}\u00bb: below INFO logins leave no usable trace.",
		"it": "Livello di log SSH \u00ab{value}\u00bb: sotto INFO gli accessi non lasciano traccia utilizzabile.",
	},
	"lnx.sshd_rhosts.honored": {
		"en": "\u00ab.rhosts\u00bb files are honoured (\u00ab{value}\u00bb): a user can declare on their own which hosts to trust.",
		"it": "I file \u00ab.rhosts\u00bb sono onorati (\u00ab{value}\u00bb): un utente puo' dichiarare da solo di quali host fidarsi.",
	},
	"lnx.sshd_rhosts.ok": {
		"en": "\u00ab.rhosts\u00bb files play no part in authentication.",
		"it": "I file \u00ab.rhosts\u00bb non partecipano all'autenticazione.",
	},
	"lnx.sshd_root.allowed": {
		"en": "Root login over SSH allowed (\u00ab{value}\u00bb): guessing a single password hands over full privilege immediately.",
		"it": "Login di root via SSH ammesso (\u00ab{value}\u00bb): un attaccante che indovina una sola password ottiene subito il massimo privilegio.",
	},
	"lnx.sshd_root.ok": {
		"en": "Direct root login over SSH is disabled.",
		"it": "Login diretto di root via SSH disabilitato.",
	},
	"lnx.sysctl.absent": {
		"en": "\u00ab/etc/sysctl.conf\u00bb missing from the backup: network parameters cannot be assessed.",
		"it": "\u00ab/etc/sysctl.conf\u00bb assente dal backup: parametri di rete non valutabili.",
	},
	"lnx.sysctl.not_declared": {
		"en": "\u00ab{what}\u00bb is not declared in sysctl.conf: it may be set under \u00ab/etc/sysctl.d/\u00bb or at runtime, which the backup does not cover.",
		"it": "\u00ab{what}\u00bb non e' dichiarato in sysctl.conf: puo' essere impostato in \u00ab/etc/sysctl.d/\u00bb o a runtime, che il backup non contiene.",
	},
	"lnx.sysctl_accept_redirects.enabled": {
		"en": "Incoming ICMP redirects are accepted ({count} parameter(s)): anyone on the segment can rewrite the host routing table.",
		"it": "Gli ICMP redirect in ingresso vengono accettati ({count} parametro/i): chiunque sul segmento puo' riscrivere la tabella di routing dell'host.",
	},
	"lnx.sysctl_accept_redirects.ok": {
		"en": "Incoming ICMP redirects are ignored.",
		"it": "Gli ICMP redirect in ingresso vengono ignorati.",
	},
	"lnx.sysctl_forward.enabled": {
		"en": "IP packet forwarding is enabled: the host can bridge two networks the perimeter keeps apart.",
		"it": "Inoltro di pacchetti IP attivo: l'host puo' fare da ponte fra due reti che il perimetro tiene separate.",
	},
	"lnx.sysctl_forward.ok": {
		"en": "IP packet forwarding is disabled.",
		"it": "Inoltro di pacchetti IP disattivato.",
	},
	"lnx.sysctl_martians.disabled": {
		"en": "Packets with an impossible source address are not logged ({count} parameter(s)): spoofing in progress leaves no trace.",
		"it": "I pacchetti con indirizzo di origine impossibile non vengono registrati ({count} parametro/i): uno spoofing in corso non lascia traccia.",
	},
	"lnx.sysctl_martians.ok": {
		"en": "Packets with an impossible source address are logged.",
		"it": "I pacchetti con indirizzo di origine impossibile vengono registrati.",
	},
	"lnx.sysctl_send_redirects.enabled": {
		"en": "The host emits ICMP redirects ({count} parameter(s)): it discloses the routing topology to anyone who probes it.",
		"it": "L'host emette ICMP redirect ({count} parametro/i): rivela la topologia di routing a chiunque lo interroghi.",
	},
	"lnx.sysctl_send_redirects.ok": {
		"en": "The host does not emit ICMP redirects.",
		"it": "L'host non emette ICMP redirect.",
	},
	"lnx.sysctl_source_route.enabled": {
		"en": "Source-routed packets are accepted ({count} parameter(s)): the sender picks the path and can bypass network controls.",
		"it": "I pacchetti con source routing vengono accettati ({count} parametro/i): il mittente sceglie il percorso e puo' aggirare i controlli di rete.",
	},
	"lnx.sysctl_source_route.ok": {
		"en": "Source-routed packets are dropped.",
		"it": "I pacchetti con source routing vengono scartati.",
	},
	"lnx.sysctl_syncookies.disabled": {
		"en": "SYN flood protection is disabled: the half-open connection queue fills up with very little traffic.",
		"it": "Protezione contro il SYN flood disattivata: la coda delle connessioni mezze aperte si riempie con poco traffico.",
	},
	"lnx.sysctl_syncookies.ok": {
		"en": "SYN flood protection is active.",
		"it": "Protezione contro il SYN flood attiva.",
	},
}

func NormalizeLang(lang string) string {
	low := strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(low, "it") {
		return "it"
	}
	if strings.HasPrefix(low, "en") {
		return "en"
	}
	return "it"
}

func RenderMessage(key string, lang string, params map[string]any) string {
	if key == "" {
		return ""
	}
	code := NormalizeLang(lang)
	entry, ok := Messages[key]
	if !ok {
		return key
	}
	tpl := entry[code]
	if tpl == "" {
		tpl = entry["it"]
	}
	if tpl == "" {
		return key
	}
	if len(params) == 0 {
		return tpl
	}
	res := tpl
	for k, v := range params {
		ph := "{" + k + "}"
		res = strings.ReplaceAll(res, ph, fmt.Sprintf("%v", v))
	}
	return res
}
