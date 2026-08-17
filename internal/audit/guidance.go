package audit

var Guidance = map[string]map[string]map[string]string{
	"check_admin_https_redirect": {
		"default": {
			"en": "enable.",
			"it": "enable.",
		},
		"impact": {
			"en": "None. The redirect opens nothing that was not already reachable.",
			"it": "Nessuno. Il redirect non apre nulla che non fosse gia' raggiungibile.",
		},
		"why": {
			"en": "If HTTP stays reachable with no redirect, an administrator typing the address without \u00abhttps://\u00bb sends the first request in cleartext \u2014 and with it, depending on the client, the session cookie.",
			"it": "Se HTTP resta raggiungibile senza redirect, l'amministratore che digita l'indirizzo senza \u00abhttps://\u00bb invia la prima richiesta in chiaro \u2014 e con essa, a seconda del client, il cookie di sessione.",
		},
	},
	"check_admin_lockout": {
		"default": {
			"en": "3 attempts, 60 seconds of lockout.",
			"it": "3 tentativi, 60 secondi di blocco.",
		},
		"impact": {
			"en": "Aggressive lockout enables a denial of service: anyone who knows an administrator's username can lock them out on purpose. It only makes sense together with \u00abtrusthost\u00bb, which limits who can even try.",
			"it": "Un blocco aggressivo si presta a un denial of service: chi conosce il nome di un amministratore puo' bloccarlo di proposito. Ha senso solo insieme a \u00abtrusthost\u00bb, che limita chi puo' tentare.",
		},
		"why": {
			"en": "With no lockout an attacker can try passwords indefinitely at whatever rate the network allows: that is the whole difference between a password guessed in days and one never guessed.",
			"it": "Senza blocco, un attaccante puo' provare password indefinitamente al ritmo che la rete consente: e' l'unica differenza fra una password indovinata in giorni e una mai indovinata.",
		},
	},
	"check_admin_ports_changed": {
		"default": {
			"en": "HTTPS 443, SSH 22.",
			"it": "HTTPS 443, SSH 22.",
		},
		"impact": {
			"en": "Every administrative connection has to name the new port, scripts and bookmarks included. Coordinate it, or half the team finds itself locked out.",
			"it": "Ogni collegamento amministrativo deve indicare la nuova porta, script e segnalibri compresi. Da coordinare, o meta' del gruppo si trova fuori.",
		},
		"why": {
			"en": "Moving the port is not security: a full scan finds it anyway. It does take the device out of mass scans, which only look at well-known ports, and that cuts brute-force noise in the logs enough to make targeted attempts visible.",
			"it": "Spostare la porta non e' sicurezza: chi fa una scansione completa la trova comunque. Toglie pero' l'apparato dalle scansioni di massa, che cercano solo le porte note, e questo riduce di molto il rumore di forza bruta nei log \u2014 rendendo visibili i tentativi mirati.",
		},
	},
	"check_admin_trusthost": {
		"default": {
			"en": "0.0.0.0/0 \u2014 no restriction.",
			"it": "0.0.0.0/0 \u2014 nessuna restrizione.",
		},
		"impact": {
			"en": "Getting the subnet wrong locks out every administrator and leaves only physical console access. Apply it while checking the source IP of your own live session.",
			"it": "Sbagliare la sottorete chiude fuori tutti gli amministratori e lascia solo l'accesso da console fisica. Applicarlo verificando l'IP sorgente della propria sessione in corso.",
		},
		"why": {
			"en": "Without \u00abtrusthost\u00bb the only barrier in front of the administration console is the password. With it, an attacker holding valid credentials \u2014 stolen or reused \u2014 still cannot present them: they have to get into the management network first.",
			"it": "Senza \u00abtrusthost\u00bb l'unica barriera davanti alla console di amministrazione e' la password. Con \u00abtrusthost\u00bb un attaccante che possiede credenziali valide, rubate o riusate, non riesce comunque a presentarle: deve prima entrare nella rete di gestione.",
		},
	},
	"check_any_any_policy": {
		"impact": {
			"en": "Tightening it is the riskiest change on this whole list: that rule almost always covers traffic nobody has inventoried any more. Turn logging on first, derive the real flows, then replace it with specific rules.",
			"it": "Restringerla e' l'intervento piu' rischioso di tutta la lista: quasi sempre quella regola copre traffico che nessuno ha piu' censito. Attivare prima il logging, ricavare i flussi reali, poi sostituirla con regole specifiche.",
		},
		"why": {
			"en": "A rule with source, destination and service all set to \u00aball\u00bb is not access control: it is routing with a firewall's logging. It voids segmentation and makes it impossible to say, after an incident, what should have been allowed through and what should not.",
			"it": "Una regola con sorgente, destinazione e servizio a \u00aball\u00bb non e' un controllo di accesso: e' un instradamento con il logging di un firewall. Annulla la segmentazione e rende impossibile dire, dopo un incidente, cosa sarebbe dovuto passare e cosa no.",
		},
	},
	"check_auto_install": {
		"default": {
			"en": "enable.",
			"it": "enable.",
		},
		"impact": {
			"en": "You lose fast USB recovery after a failure: make sure an alternative recovery procedure exists.",
			"it": "Si perde il ripristino rapido da USB in caso di guasto: verificare di avere una procedura di recupero alternativa.",
		},
		"why": {
			"en": "With auto-install on, a USB stick inserted at boot replaces the configuration or the firmware with no authentication. It turns thirty seconds of physical access into full control of the device.",
			"it": "Con l'auto-install attivo, una chiavetta USB inserita al riavvio sostituisce configurazione o firmware senza autenticarsi. Trasforma un accesso fisico di trenta secondi nel controllo completo dell'apparato.",
		},
	},
	"check_boundary_protection": {
		"impact": {
			"en": "Naming the destinations can break undocumented service publications. Derive them from the policy's own logs before tightening it.",
			"it": "Specificare le destinazioni puo' interrompere pubblicazioni di servizi non documentate. Ricavarle dai log della policy prima di restringerla.",
		},
		"why": {
			"en": "An inbound policy from WAN with destination \u00aball\u00bb makes every internal host with a route reachable from outside, including the networks nobody thinks of as exposed. The exposure grows on its own every time a VLAN is added.",
			"it": "Una policy in ingresso da WAN con destinazione \u00aball\u00bb rende raggiungibile dall'esterno qualunque host interno che abbia una rotta, comprese le reti che nessuno considera esposte. L'esposizione cresce da sola ogni volta che si aggiunge una VLAN.",
		},
	},
	"check_cpu_log_threshold": {
		"default": {
			"en": "disable.",
			"it": "disable.",
		},
		"impact": {
			"en": "Only a few extra log lines.",
			"it": "Solo qualche riga di log in piu'.",
		},
		"why": {
			"en": "Average load hides the saturation of a single core, which on a firewall is the classic symptom of a looping process or an attack aimed at one specific function. Without this alarm the problem shows up only as unexplained slowness.",
			"it": "Il carico medio nasconde la saturazione di un singolo core, che su un firewall e' il sintomo tipico di un processo in loop o di un attacco mirato a una funzione specifica. Senza questo allarme il problema si manifesta come lentezza inspiegabile.",
		},
	},
	"check_dns_configured": {
		"default": {
			"en": "FortiGuard public resolvers: the check passes even though nobody chose a DNS.",
			"it": "risolutori pubblici di FortiGuard: il controllo passa anche senza che nessuno abbia scelto un DNS.",
		},
		"impact": {
			"en": "None: changing the resolvers does not touch user traffic, which uses its own.",
			"it": "Nessuno: cambiare i risolutori non tocca il traffico degli utenti, che usa i propri.",
		},
		"why": {
			"en": "The device resolves names on its own behalf: updates, certificate validation, threat-intelligence feeds, FQDN objects in policies. Without reliable resolvers those functions degrade silently, and an uncontrolled DNS can hijack the FQDN objects.",
			"it": "L'apparato risolve nomi per proprio conto: aggiornamenti, verifica dei certificati, feed di threat intelligence, oggetti FQDN nelle policy. Senza risolutori affidabili quelle funzioni degradano in silenzio, e un DNS non controllato puo' dirottare gli oggetti FQDN.",
		},
	},
	"check_event_logging": {
		"default": {
			"en": "enable.",
			"it": "enable.",
		},
		"impact": {
			"en": "Volume is negligible next to traffic logging.",
			"it": "Volume trascurabile rispetto al log di traffico.",
		},
		"why": {
			"en": "Event logs are the record of who did what on the device: logins, configuration changes, HA failovers. Traffic logs say what passed through; these say who changed the rules \u2014 and that is the half you need after unauthorised access.",
			"it": "Gli event log sono la traccia di chi ha fatto cosa sull'apparato: accessi, modifiche di configurazione, commutazioni HA. Il log del traffico dice cosa e' passato, questo dice chi ha cambiato le regole \u2014 ed e' la meta' che serve dopo un accesso non autorizzato.",
		},
	},
	"check_gui_hostname_display": {
		"default": {
			"en": "disable.",
			"it": "disable.",
		},
		"impact": {
			"en": "Anyone administering several identical devices loses the visual cue on the login page and has to trust the URL. After authentication the hostname is still visible.",
			"it": "Chi amministra piu' apparati identici perde il riferimento visivo sulla pagina di login e deve fidarsi dell'URL. Dopo l'autenticazione l'hostname resta visibile.",
		},
		"why": {
			"en": "The login page is pre-authentication: it is reachable by anyone who gets to the address, not only by those holding credentials. Showing the hostname there hands the device name \u2014 and with it the role and site, given how devices get named \u2014 to whoever is merely probing.",
			"it": "La pagina di login e' pre-autenticazione: e' raggiungibile da chiunque arrivi all'indirizzo, non solo da chi ha credenziali. Mostrarvi l'hostname regala il nome dell'apparato \u2014 e con esso ruolo e sede, visto come si nominano gli apparati \u2014 a chi sta solo sondando.",
		},
	},
	"check_ha_configured": {
		"impact": {
			"en": "Monitoring a flapping interface produces constant failovers, worse than the failure it was meant to cover. Monitor only stable, redundant links.",
			"it": "Monitorare un'interfaccia instabile produce commutazioni continue, peggio del guasto che si voleva coprire. Monitorare solo i collegamenti stabili e ridondati.",
		},
		"why": {
			"en": "A cluster watching only node health does not fail over when a data link drops: the active node still looks healthy and keeps holding traffic on a port that no longer forwards anything. Interface monitoring is what makes failover real.",
			"it": "Un cluster che sorveglia solo lo stato del nodo non commuta quando cade un collegamento dati: il nodo attivo resta \u00absano\u00bb e continua a tenere il traffico su una porta che non passa piu' nulla. Il monitoraggio delle interfacce e' cio' che rende reale il failover.",
		},
	},
	"check_hostname": {
		"impact": {
			"en": "None on traffic. It changes the CLI prompt and the \u00abdevname\u00bb field in the logs: update the SIEM filters.",
			"it": "Nessuno sul traffico. Cambia il prompt CLI e il campo \u00abdevname\u00bb nei log: aggiornare i filtri del SIEM.",
		},
		"why": {
			"en": "The factory name carries the model, and often the serial number: it is the first useful piece of information for anyone hunting a targeted exploit. It is also why, with several identical devices, the log does not say which one produced the event.",
			"it": "Il nome di fabbrica contiene il modello, e spesso il numero di serie: e' la prima informazione utile a chi cerca un exploit mirato. Ed e' anche il motivo per cui, con piu' apparati identici, il log non dice quale ha generato l'evento.",
		},
	},
	"check_idle_timeout": {
		"default": {
			"en": "5 minutes.",
			"it": "5 minuti.",
		},
		"impact": {
			"en": "Anyone working long sessions in the GUI gets logged out mid-task. Annoying, never destructive: FortiOS does not apply a half-written configuration.",
			"it": "Chi lavora a lungo sulla GUI viene disconnesso a meta' di un'operazione. Fastidioso, mai distruttivo: FortiOS non applica una configurazione a meta'.",
		},
		"why": {
			"en": "An administrative session left open is an already authenticated session available to whoever reaches that workstation, and it stays valid even if the password was changed or the account revoked in the meantime.",
			"it": "Una sessione amministrativa lasciata aperta e' una sessione gia' autenticata a disposizione di chiunque arrivi a quella postazione, e resta valida anche se nel frattempo la password e' stata cambiata o l'account revocato.",
		},
	},
	"check_inbound_admin_ports": {
		"impact": {
			"en": "Anyone administering remotely without a VPN loses access: set up the VPN or bastion first, or you risk locking yourself out.",
			"it": "Chi amministra da remoto senza VPN perde l'accesso: predisporre prima VPN o bastion, altrimenti si rischia di chiudersi fuori.",
		},
		"why": {
			"en": "SSH and RDP reachable from the Internet are found by mass scans within hours and brute forced continuously. Even with strong credentials they remain ransomware's favourite way in.",
			"it": "SSH e RDP raggiungibili da Internet vengono trovati dalle scansioni di massa nel giro di ore e sottoposti a forza bruta in continuo. Anche con credenziali robuste restano la porta d'ingresso preferita del ransomware.",
		},
	},
	"check_intrazone_deny": {
		"default": {
			"en": "deny \u2014 intra-zone traffic is blocked out of the box; if it is allowed, someone opened it.",
			"it": "deny \u2014 il traffico intra-zona e' bloccato di fabbrica; se e' permesso, qualcuno l'ha aperto.",
		},
		"impact": {
			"en": "High: traffic between the zone's interfaces stops until the matching policies are written. Do it in a maintenance window.",
			"it": "Alto: il traffico fra le interfacce della zona si ferma finche' non si scrivono le policy corrispondenti. Da fare in finestra di manutenzione.",
		},
		"why": {
			"en": "With \u00abintrazone allow\u00bb, traffic between two interfaces of the same zone crosses no policy at all: it is neither filtered nor logged. It is a shortcut that stays invisible, because nothing about it shows up in the rule list.",
			"it": "Con \u00abintrazone allow\u00bb il traffico fra due interfacce della stessa zona non attraversa alcuna policy: non e' filtrato e non e' registrato. E' una scorciatoia che rimane invisibile, perche' nell'elenco delle regole non compare nulla.",
		},
	},
	"check_ios_aaa_accounting_commands": {
		"impact": {
			"en": "It generates traffic to the TACACS+ server on every command. If the server stops answering, \u00abstart-stop\u00bb can slow the session noticeably.",
			"it": "Genera traffico verso il server TACACS+ a ogni comando. Se il server non risponde, con \u00abstart-stop\u00bb la sessione puo' rallentare sensibilmente.",
		},
		"why": {
			"en": "Accounting of level-15 commands is the only record of who ran what. Without it the log says someone logged in but not what they changed: after an outage there is no way back to the command that caused it.",
			"it": "L'accounting dei comandi a livello 15 e' l'unica traccia di chi ha eseguito cosa. Senza, il log dice che qualcuno e' entrato ma non cosa ha cambiato: dopo un'interruzione non e' possibile risalire al comando che l'ha causata.",
		},
	},
	"check_ios_aaa_authentication_login": {
		"impact": {
			"en": "The right fallback is \u00ablocal\u00bb, which needs at least one local user defined: create it first, or a TACACS+ outage makes the device unreachable.",
			"it": "Il fallback corretto e' \u00ablocal\u00bb, che richiede almeno un utente locale definito: crearlo prima, o un guasto del server TACACS+ rende l'apparato inaccessibile.",
		},
		"why": {
			"en": "The login method decides where credentials get verified. A method with a \u00abnone\u00bb fallback is worse than no AAA at all: it looks configured, but when the server is unreachable it lets anyone in without asking.",
			"it": "Il metodo di login determina da dove vengono verificate le credenziali. Un metodo con fallback \u00abnone\u00bb e' peggio dell'assenza di AAA: sembra configurato, ma in caso di server irraggiungibile lascia entrare senza chiedere nulla.",
		},
	},
	"check_ios_aaa_new_model": {
		"impact": {
			"en": "Enabling it changes how logins are evaluated immediately, and can lock out anyone using line passwords. Define the methods with a \u00ablocal\u00bb fallback first, keeping a session open.",
			"it": "Attivarlo cambia immediatamente il modo in cui vengono valutati gli accessi e puo' chiudere fuori chi usava le password di linea. Definire prima i metodi con fallback \u00ablocal\u00bb, tenendo aperta una sessione.",
		},
		"why": {
			"en": "Without \u00abaaa new-model\u00bb the device authenticates with line passwords and local users: credentials living in each device's own configuration, not centrally revocable and not traceable to a person. It is the precondition for nearly every other access control.",
			"it": "Senza \u00abaaa new-model\u00bb l'apparato si autentica con le password di linea e gli utenti locali: credenziali che vivono nella configurazione di ogni singolo apparato, non revocabili centralmente e non tracciabili a una persona. E' il presupposto di quasi tutti gli altri controlli di accesso.",
		},
	},
	"check_ios_aux_no_exec": {
		"impact": {
			"en": "You lose emergency access over AUX. Only relevant if a procedure actually uses it.",
			"it": "Si perde l'accesso di emergenza via AUX. Rilevante solo se esiste davvero una procedura che lo usa.",
		},
		"why": {
			"en": "The auxiliary port is often wired to a modem or a console server and then forgotten. With the EXEC process active it offers full administrative access that appears in no review of network access paths.",
			"it": "La porta ausiliaria e' spesso collegata a un modem o a un server di console e poi dimenticata. Con il processo EXEC attivo offre un accesso amministrativo completo che non compare in nessuna revisione degli accessi in rete.",
		},
	},
	"check_ios_banner_login": {
		"impact": {
			"en": "None.",
			"it": "Nessuno.",
		},
		"why": {
			"en": "The login banner appears before authentication and is the notice that makes any subsequent access unauthorised. It must not reveal model, version or owner: that would be handing information to whoever is probing the device.",
			"it": "Il banner di login compare prima dell'autenticazione ed e' l'avvertenza che qualifica come non autorizzato ogni accesso successivo. Non deve rivelare modello, versione o proprietario: sarebbero informazioni offerte a chi sta sondando l'apparato.",
		},
	},
	"check_ios_banner_motd": {
		"impact": {
			"en": "None.",
			"it": "Nessuno.",
		},
		"why": {
			"en": "The MOTD is shown on every connection. It carries the same legal weight as the login banner and, being editable without touching authentication, is where maintenance windows get announced.",
			"it": "Il MOTD e' il messaggio mostrato a ogni connessione. Ha lo stesso valore legale del banner di login e, essendo modificabile senza toccare l'autenticazione, e' il posto dove annunciare finestre di manutenzione.",
		},
	},
	"check_ios_cdp": {
		"default": {
			"en": "enabled.",
			"it": "attivo.",
		},
		"impact": {
			"en": "Cisco IP phones and access points use CDP to learn the voice VLAN and negotiate PoE: disabling it globally can leave them without service. Disabling it per interface on user ports is the usual compromise.",
			"it": "Telefoni IP e access point Cisco usano CDP per ricevere la VLAN voce e negoziare il PoE: disabilitarlo globalmente puo' lasciarli senza servizio. Disabilitarlo per interfaccia sulle porte utente e' il compromesso usuale.",
		},
		"why": {
			"en": "CDP announces, in cleartext, the model, IOS version, device name, management address and port: precisely the list needed to pick an exploit. Anyone plugging into a socket receives it without authenticating.",
			"it": "CDP annuncia in chiaro modello, versione di IOS, nome dell'apparato, indirizzo di gestione e porta: e' esattamente l'elenco che serve per scegliere un exploit. Chiunque si colleghi a una presa lo riceve senza autenticarsi.",
		},
	},
	"check_ios_console_exec_timeout": {
		"default": {
			"en": "10 minutes.",
			"it": "10 minuti.",
		},
		"impact": {
			"en": "None, beyond having to re-authenticate during long console sessions.",
			"it": "Nessuno, salvo dover riautenticarsi durante interventi lunghi da console.",
		},
		"why": {
			"en": "The console is often permanently wired to a network-reachable terminal server: a session left open there is available to anyone who reaches that server, bypassing the device's authentication entirely.",
			"it": "La console e' spesso collegata in permanenza a un server seriale raggiungibile in rete: una sessione lasciata aperta li' e' accessibile a chiunque arrivi a quel server, senza passare da alcuna autenticazione dell'apparato.",
		},
	},
	"check_ios_domain_name": {
		"impact": {
			"en": "Changing the domain after generating the keys invalidates them: SSH has to be re-enabled by regenerating them.",
			"it": "Cambiare il dominio dopo aver generato le chiavi le invalida: SSH va riabilitato rigenerandole.",
		},
		"why": {
			"en": "IOS derives the RSA key pair name from the hostname and the domain: with no domain the keys cannot be generated and SSH cannot start. Not a security control in itself, but the precondition that makes the rest applicable.",
			"it": "IOS deriva il nome della coppia di chiavi RSA da hostname e dominio: senza dominio le chiavi non si generano e SSH non puo' partire. Non e' un controllo di sicurezza in se', e' il prerequisito che rende applicabile tutto il resto.",
		},
	},
	"check_ios_enable_secret": {
		"impact": {
			"en": "If both are present IOS uses \u00absecret\u00bb and ignores \u00abpassword\u00bb: set the secret and verify access before removing the old line.",
			"it": "Se sono presenti entrambe, IOS usa \u00absecret\u00bb e ignora \u00abpassword\u00bb: impostare la secret e verificare l'accesso prima di rimuovere la vecchia riga.",
		},
		"why": {
			"en": "\u00abenable password\u00bb is stored with type-7 encoding, which is reversible: online decoders have existed for twenty years. Anyone who reads the configuration \u2014 a backup, a ticket, a colleague \u2014 recovers the privileged password in cleartext. \u00abenable secret\u00bb uses a non-invertible hash.",
			"it": "\u00abenable password\u00bb e' memorizzata con la cifratura di tipo 7, reversibile: esistono decodificatori online da vent'anni. Chiunque legga la configurazione \u2014 un backup, un ticket, un collega \u2014 ottiene la password privilegiata in chiaro. \u00abenable secret\u00bb usa un hash non invertibile.",
		},
	},
	"check_ios_local_user_privilege": {
		"impact": {
			"en": "Dropping users to \u00abprivilege 1\u00bb means they must know the enable secret: make sure it is known and documented first, or administrators are left with read-only privileges.",
			"it": "Riportare gli utenti a \u00abprivilege 1\u00bb impone di conoscere la enable secret: verificare che sia nota e documentata prima, o gli amministratori restano con soli privilegi di lettura.",
		},
		"why": {
			"en": "A \u00abprivilege 15\u00bb user lands straight in privileged EXEC: the enable password is never asked and the second control step disappears. Any compromise of that account is immediately total.",
			"it": "Un utente a \u00abprivilege 15\u00bb entra direttamente in EXEC privilegiato: la password di enable non viene mai chiesta e il secondo fattore di controllo sparisce. Ogni compromissione di quell'account e' immediatamente totale.",
		},
	},
	"check_ios_logging_buffered": {
		"default": {
			"en": "4096 bytes on many platforms.",
			"it": "4096 byte su molte piattaforme.",
		},
		"impact": {
			"en": "It consumes RAM. On memory-constrained devices a very large buffer takes resources away from networking functions.",
			"it": "Occupa RAM. Su apparati con poca memoria un buffer molto grande sottrae risorse alle funzioni di rete.",
		},
		"why": {
			"en": "The local buffer is what you read when the remote collector is unreachable, which is often exactly when you need it. Too small a buffer overwrites itself before anyone gets to look.",
			"it": "Il buffer locale e' cio' che si legge quando il collector remoto e' irraggiungibile, che e' spesso il momento in cui serve. Un buffer troppo piccolo si sovrascrive prima che qualcuno arrivi a guardarlo.",
		},
	},
	"check_ios_logging_console": {
		"default": {
			"en": "debugging \u2014 everything.",
			"it": "debugging \u2014 tutto.",
		},
		"impact": {
			"en": "Anyone working from the console sees fewer live messages. They all remain in the buffer and on syslog.",
			"it": "Chi lavora da console vede meno messaggi in tempo reale. Restano tutti nel buffer e sul syslog.",
		},
		"why": {
			"en": "The console is a slow serial interface, and IOS waits for each message to be written. At a verbose level, during a network event the device spends its time writing to the console instead of routing: a documented way to take a router down under load.",
			"it": "La console e' un'interfaccia seriale lenta, e IOS attende che ogni messaggio sia stato scritto. Con un livello verboso, durante un evento di rete l'apparato passa tempo a scrivere sulla console invece che a instradare: e' un modo documentato di far cadere un router sotto carico.",
		},
	},
	"check_ios_logging_host": {
		"impact": {
			"en": "It adds steady UDP traffic towards the collector. On slow WAN links, tune the severity level sent.",
			"it": "Aggiunge traffico UDP costante verso il collector. Su collegamenti geografici lenti valutare il livello di severita' inviato.",
		},
		"why": {
			"en": "An IOS device's buffer is small and volatile: it empties at every reboot and overwrites itself within hours on a busy device. With no remote collector, the record of the event that caused the reboot disappears along with the reboot.",
			"it": "Il buffer di un apparato IOS e' piccolo e volatile: si svuota a ogni riavvio e si sovrascrive da solo in poche ore su un apparato attivo. Senza collector remoto, la traccia dell'evento che ha causato il riavvio sparisce con il riavvio stesso.",
		},
	},
	"check_ios_logging_source_interface": {
		"impact": {
			"en": "The chosen interface \u2014 typically a loopback \u2014 has to be reachable from the collector, otherwise the logs stop arriving.",
			"it": "L'interfaccia scelta \u2014 tipicamente una loopback \u2014 deve essere raggiungibile dal collector, altrimenti i log smettono di arrivare.",
		},
		"why": {
			"en": "Without a pinned source interface, the IP the logs come from changes with whatever route is chosen at the time. The collector sees one device under several identities, source-based filters break and correlations fall apart.",
			"it": "Senza interfaccia sorgente fissa, l'IP da cui arrivano i log cambia con la rotta scelta al momento. Il collector vede lo stesso apparato sotto identita' diverse, i filtri per sorgente saltano e le correlazioni si spezzano.",
		},
	},
	"check_ios_logging_trap": {
		"default": {
			"en": "informational.",
			"it": "informational.",
		},
		"impact": {
			"en": "\u00abinformational\u00bb increases volume considerably: size the collector's retention accordingly.",
			"it": "\u00abinformational\u00bb aumenta sensibilmente il volume: dimensionare la ritenzione del collector.",
		},
		"why": {
			"en": "\u00ablogging trap\u00bb decides how much is forwarded to the remote syslog. Set too high \u2014 \u00abemergencies\u00bb, \u00abalerts\u00bb \u2014 neither logins, nor configuration changes, nor interface state changes arrive: precisely what you need to correlate.",
			"it": "\u00ablogging trap\u00bb decide quanto viene inoltrato al syslog remoto. Impostato troppo in alto \u2014 \u00abemergencies\u00bb, \u00abalerts\u00bb \u2014 non arrivano ne' i login, ne' le modifiche di configurazione, ne' i cambi di stato delle interfacce: esattamente cio' che serve correlare.",
		},
	},
	"check_ios_login_logging": {
		"impact": {
			"en": "Negligible volume, except on devices already under attack \u2014 where that is precisely the point.",
			"it": "Volume trascurabile, salvo su apparati gia' sotto attacco \u2014 dove pero' e' precisamente il punto.",
		},
		"why": {
			"en": "Without \u00ablogin on-failure log\u00bb a brute-force attack leaves no trace at all: there is no way to notice it, during or after. Without \u00abon-success\u00bb there is no telling which attempt eventually worked.",
			"it": "Senza \u00ablogin on-failure log\u00bb un attacco a forza bruta non lascia alcuna traccia: non c'e' modo di accorgersene ne' durante ne' dopo. Senza \u00abon-success\u00bb non si sa quale tentativo, alla fine, e' andato a buon fine.",
		},
	},
	"check_ios_ntp_authentication": {
		"impact": {
			"en": "The keys must match exactly on server and client: if they do not, synchronisation stops silently and drift resumes.",
			"it": "Le chiavi vanno configurate identiche su server e client: se non corrispondono la sincronizzazione si ferma in silenzio, e la deriva riparte.",
		},
		"why": {
			"en": "Unauthenticated NTP takes the time from any source claiming to be a server. Shifting the clock is a way to expire valid certificates, resurrect revoked ones and make the logs incoherent precisely during an intrusion.",
			"it": "NTP non autenticato accetta l'ora da qualunque sorgente che si dichiari server. Spostare l'orologio serve a far scadere certificati validi, riabilitarne di revocati e rendere incoerenti i log proprio durante un'intrusione.",
		},
	},
	"check_ios_ntp_servers": {
		"impact": {
			"en": "The first sync can move the clock abruptly. On devices terminating IPsec tunnels a jump can force renegotiation.",
			"it": "La prima sincronizzazione puo' spostare l'orologio bruscamente. Su apparati che terminano tunnel IPsec un salto puo' rinegoziare le associazioni.",
		},
		"why": {
			"en": "An unsynchronised clock makes that device's logs impossible to place in time against every other device: the sequence of events, which is what you reconstruct after an incident, becomes unreliable. Two sources matter because a single one cannot be cross-checked.",
			"it": "Un orologio non sincronizzato rende i log di quell'apparato incollocabili nel tempo rispetto a tutti gli altri: la sequenza degli eventi, che e' cio' che si ricostruisce dopo un incidente, diventa inattendibile. Due sorgenti servono perche' una sola non e' verificabile.",
		},
	},
	"check_ios_proxy_arp": {
		"default": {
			"en": "on, per interface.",
			"it": "attivo su ogni interfaccia.",
		},
		"impact": {
			"en": "Hosts configured with the wrong netmask stop reaching other networks, because they were leaning on proxy ARP without knowing. These are latent faults that surface all at once.",
			"it": "Host configurati con una maschera sbagliata smettono di raggiungere le altre reti, perche' si appoggiavano al proxy ARP senza saperlo. Sono guasti latenti che emergono tutti insieme.",
		},
		"why": {
			"en": "With proxy ARP the router answers ARP requests for addresses that are not its own, making hosts on other networks look local to the segment. It stretches the broadcast domain past its designed boundary and partly defeats segmentation.",
			"it": "Con proxy ARP il router risponde alle richieste ARP per indirizzi che non gli appartengono, facendo apparire host di altre reti come se fossero sul segmento locale. Estende il dominio di broadcast oltre il confine progettato e vanifica in parte la segmentazione.",
		},
	},
	"check_ios_service_dhcp": {
		"default": {
			"en": "enabled.",
			"it": "attivo.",
		},
		"impact": {
			"en": "High if the device really hands out addresses, even to a single management VLAN or a test pool. Check for \u00abip dhcp pool\u00bb before disabling.",
			"it": "Alto se l'apparato eroga davvero indirizzi, anche solo a una VLAN di gestione o a un pool di test. Verificare la presenza di \u00abip dhcp pool\u00bb prima di disabilitare.",
		},
		"why": {
			"en": "If addressing is served elsewhere, a running DHCP service is pure attack surface: it answers requests on the network and has a vulnerability history of its own. It can also conflict with the legitimate server.",
			"it": "Se l'indirizzamento e' erogato altrove, il servizio DHCP attivo e' solo superficie di attacco: risponde a richieste sulla rete e ha un proprio storico di vulnerabilita'. Puo' anche entrare in conflitto col server legittimo.",
		},
	},
	"check_ios_service_pad": {
		"default": {
			"en": "enabled.",
			"it": "attivo.",
		},
		"impact": {
			"en": "None.",
			"it": "Nessuno.",
		},
		"why": {
			"en": "PAD exists for X.25, a protocol absent from any production network today. It stays on for historical compatibility, reachable code that nobody uses, reviews or patches: the definition of pointless attack surface.",
			"it": "PAD serve per X.25, protocollo che non esiste piu' in alcuna rete in produzione. Resta attivo per compatibilita' storica ed e' codice raggiungibile che nessuno usa, verifica o aggiorna: la definizione di superficie di attacco inutile.",
		},
	},
	"check_ios_service_password_encryption": {
		"default": {
			"en": "disabled.",
			"it": "disabilitato.",
		},
		"impact": {
			"en": "None. Not to be mistaken for real protection: it is reversible, and \u00absecret\u00bb is what you want wherever possible.",
			"it": "Nessuno. Da non confondere con una protezione reale: e' reversibile, e serve \u00absecret\u00bb dove possibile.",
		},
		"why": {
			"en": "Without this directive line passwords and some protocol credentials stay readable in cleartext in the configuration, which travels through backups, tickets and repositories. Type-7 encoding is weak, but it stops casual reading by anyone merely looking.",
			"it": "Senza questa direttiva le password di linea e alcune credenziali di protocollo restano leggibili in chiaro nella configurazione, che circola in backup, ticket e repository. La cifratura di tipo 7 e' debole, ma toglie la lettura accidentale a chi si limita a guardare.",
		},
	},
	"check_ios_service_timestamps": {
		"default": {
			"en": "uptime.",
			"it": "uptime.",
		},
		"impact": {
			"en": "None. Add \u00abshow-timezone\u00bb if devices sit in different time zones, otherwise the date is ambiguous.",
			"it": "Nessuno. Aggiungere \u00abshow-timezone\u00bb se gli apparati sono su fusi diversi, altrimenti la data e' ambigua.",
		},
		"why": {
			"en": "With uptime-based timestamps a message reads \u00ab2w3d\u00bb instead of a date: working out when it happened needs the boot time and hand arithmetic. Correlating events across devices becomes impractical.",
			"it": "Con i timestamp basati sull'uptime, un messaggio riporta \u00ab2w3d\u00bb invece di una data: per sapere quando e' accaduto servono l'ora del riavvio e un calcolo a mano. Correlare eventi fra piu' apparati diventa impraticabile.",
		},
	},
	"check_ios_snmp_community_acl": {
		"impact": {
			"en": "Leaving a collector out of the list silently starves it of data. Enumerate them all first.",
			"it": "Dimenticare un collector nella lista lo lascia senza dati, in silenzio. Enumerarli tutti prima.",
		},
		"why": {
			"en": "A community with no access-list answers anyone able to send the device a UDP packet \u2014 and UDP source addresses are easy to forge. The ACL is what confines querying to the monitoring systems.",
			"it": "Una community senza access-list risponde a chiunque possa inviare un pacchetto UDP all'apparato \u2014 e UDP si falsifica facilmente come sorgente. L'ACL e' quello che limita l'interrogazione ai soli sistemi di monitoraggio.",
		},
	},
	"check_ios_snmp_default_community": {
		"impact": {
			"en": "Every monitoring system needs the new community, otherwise it silently stops collecting.",
			"it": "Ogni sistema di monitoraggio va aggiornato con la nuova community, altrimenti smette di raccogliere senza segnalarlo.",
		},
		"why": {
			"en": "\u00abpublic\u00bb and \u00abprivate\u00bb are the first values any scanner tries. On IOS a read community exposes the ARP table, interfaces, routes and CDP neighbours: a complete map of the network, handed over with no authentication.",
			"it": "\u00abpublic\u00bb e \u00abprivate\u00bb sono i primi valori provati da qualunque scanner. Su IOS una community di lettura espone tabella ARP, interfacce, rotte e vicini CDP: la mappa completa della rete, offerta senza autenticazione.",
		},
	},
	"check_ios_snmp_readwrite": {
		"impact": {
			"en": "Some provisioning tools use SNMP RW to write configuration: check before removing it, or those workflows stop.",
			"it": "Alcuni strumenti di provisioning usano SNMP RW per scrivere la configurazione: verificare prima di rimuoverla, o quei flussi si fermano.",
		},
		"why": {
			"en": "An RW community is not monitoring: it allows changing the configuration over SNMP and, historically, downloading or replacing it over TFTP. Under SNMPv2c that community travels in cleartext at every poll.",
			"it": "Una community RW non e' monitoraggio: consente di modificare la configurazione via SNMP e, storicamente, di scaricarla o sostituirla via TFTP. Con SNMPv2c quella community viaggia in chiaro a ogni polling.",
		},
	},
	"check_ios_snmpv3_privacy": {
		"impact": {
			"en": "Encryption and authentication cost CPU at every poll: on older devices with short intervals the effect is measurable.",
			"it": "Cifratura e autenticazione costano CPU a ogni polling: su apparati datati con intervalli brevi l'effetto e' misurabile.",
		},
		"why": {
			"en": "SNMPv3 without \u00abpriv\u00bb authenticates but does not encrypt: the data travels readable. With AES at 128 bits or above both the authentication and the payload are protected, and SNMP stops being a reconnaissance channel.",
			"it": "SNMPv3 senza \u00abpriv\u00bb autentica ma non cifra: i dati viaggiano leggibili. Con AES a 128 bit o piu' sia l'autenticazione sia il contenuto sono protetti, e SNMP smette di essere un canale di ricognizione.",
		},
	},
	"check_ios_source_route": {
		"default": {
			"en": "enabled.",
			"it": "attivo.",
		},
		"impact": {
			"en": "None in practice. Some very old diagnostic tools relied on it.",
			"it": "Nessuno in pratica. Qualche strumento diagnostico molto vecchio lo usava.",
		},
		"why": {
			"en": "Source routing lets the sender choose the path of their own packets: that is how you reach networks normal routing would not expose, and how path-based controls get bypassed. It has no legitimate use in modern networks.",
			"it": "Il source routing lascia al mittente la scelta del percorso dei propri pacchetti: e' cosi' che si raggiungono reti che l'instradamento normale non esporrebbe e si aggirano i controlli basati sul percorso. Non ha usi legittimi nelle reti moderne.",
		},
	},
	"check_ios_ssh_auth_retries": {
		"default": {
			"en": "3.",
			"it": "3.",
		},
		"impact": {
			"en": "Negligible: anyone mistyping simply reconnects.",
			"it": "Trascurabile: chi sbaglia la password riapre la sessione.",
		},
		"why": {
			"en": "Every attempt allowed within the same session multiplies the passwords testable without the cost of reopening the connection. Limiting them does not stop brute force but slows it and makes it visible in the logs.",
			"it": "Ogni tentativo consentito nella stessa sessione moltiplica le password provabili senza il costo di riaprire la connessione. Limitarli non ferma la forza bruta ma la rallenta e la rende visibile nei log.",
		},
	},
	"check_ios_ssh_timeout": {
		"default": {
			"en": "120 seconds.",
			"it": "120 secondi.",
		},
		"impact": {
			"en": "On very slow links or with multi-factor authentication 60 seconds can be tight: check against your own login flow.",
			"it": "Su collegamenti molto lenti o con autenticazione a piu' fattori 60 secondi possono essere stretti: verificare col proprio flusso di login.",
		},
		"why": {
			"en": "The timeout bounds how long a connection can stay open without completing authentication. At the 120-second default, a handful of parallel connections hold every vty line and lock administrators out.",
			"it": "Il timeout limita quanto a lungo una connessione puo' restare aperta senza completare l'autenticazione. Con il default di 120 secondi, poche connessioni parallele tengono occupate tutte le linee vty e lasciano fuori gli amministratori.",
		},
	},
	"check_ios_ssh_version": {
		"default": {
			"en": "compatibility mode: accepts both 1 and 2.",
			"it": "modalita' compatibile: accetta 1 e 2.",
		},
		"impact": {
			"en": "Very old SSH clients stop connecting. In practice no supported tool still uses SSHv1.",
			"it": "Client SSH molto vecchi non si collegano piu'. In pratica nessuno strumento ancora supportato usa SSHv1.",
		},
		"why": {
			"en": "SSH version 1 has structural weaknesses in its integrity checking that allow injecting commands into an encrypted session. This is not about longer keys: the protocol is broken and has to be excluded.",
			"it": "SSH versione 1 ha debolezze strutturali nel controllo di integrita' che permettono l'inserimento di comandi in una sessione cifrata. Non e' una questione di chiavi piu' lunghe: il protocollo e' rotto e va escluso.",
		},
	},
	"check_ios_tcp_keepalives": {
		"default": {
			"en": "disabled.",
			"it": "disabilitati.",
		},
		"impact": {
			"en": "None.",
			"it": "Nessuno.",
		},
		"why": {
			"en": "Without keepalives an administrative session that ended badly \u2014 cable pulled, laptop closed \u2014 stays open and authenticated on the device side. It holds a vty line and, in unlucky cases, can be hijacked.",
			"it": "Senza keepalive, una sessione amministrativa interrotta male \u2014 cavo staccato, portatile chiuso \u2014 resta aperta e autenticata lato apparato. Occupa una linea vty e, in casi sfortunati, e' dirottabile.",
		},
	},
	"check_ios_tunnel_interfaces": {
		"impact": {
			"en": "Removing a tunnel in use breaks whatever connectivity it carries, often to a branch or a supplier. Something to verify, not to delete on sight.",
			"it": "Rimuovere un tunnel in uso interrompe la connettivita' che trasporta, spesso verso una sede o un fornitore. Da verificare, non da eliminare d'ufficio.",
		},
		"why": {
			"en": "A tunnel encapsulates traffic and carries it off the monitored path: perimeter policies see a single flow to the endpoint, not what it contains. A legitimate tunnel needs documenting; an unexpected one is an exit that bypasses every control.",
			"it": "Un tunnel incapsula traffico e lo porta fuori dal percorso sorvegliato: le policy perimetrali vedono un solo flusso verso l'endpoint, non cio' che contiene. Un tunnel legittimo va documentato; uno non previsto e' una via d'uscita che aggira ogni controllo.",
		},
	},
	"check_ios_username_secret": {
		"impact": {
			"en": "Passwords must be re-entered: the hash cannot be derived from the existing ones. Use \u00abalgorithm-type sha256\u00bb where the release supports it.",
			"it": "Le password vanno reimpostate: l'hash non si ricava da quelle esistenti. Usare \u00abalgorithm-type sha256\u00bb dove la versione lo supporta.",
		},
		"why": {
			"en": "\u00abusername ... password\u00bb keeps the credential in cleartext or type 7, both recoverable by anyone who reads the configuration. \u00absecret\u00bb applies a hash: whoever gets the backup does not get the passwords.",
			"it": "\u00abusername ... password\u00bb conserva la credenziale in chiaro o in tipo 7, entrambi recuperabili da chi legge la configurazione. \u00absecret\u00bb applica un hash: chi ottiene il backup non ottiene le password.",
		},
	},
	"check_ios_vty_access_class": {
		"impact": {
			"en": "A wrong ACL locks everyone out and leaves only the physical console. Apply it after checking your own source address is included, with \u00abreload in 10\u00bb armed as a safety net.",
			"it": "Una ACL sbagliata chiude fuori tutti e lascia solo la console fisica. Applicarla verificando che il proprio indirizzo sorgente sia incluso, e con \u00abreload in 10\u00bb attivo come rete di sicurezza.",
		},
		"why": {
			"en": "Without an access-class the device's SSH port answers anyone who can reach it, and every login attempt consumes one of the few vty lines available: repeated connections alone can lock administrators out without guessing any password.",
			"it": "Senza access-class la porta SSH dell'apparato risponde a chiunque riesca a raggiungerla, e ogni tentativo di accesso consuma una delle poche linee vty disponibili: bastano connessioni ripetute per lasciare fuori gli amministratori senza indovinare alcuna password.",
		},
	},
	"check_ios_vty_exec_timeout": {
		"default": {
			"en": "10 minutes.",
			"it": "10 minuti.",
		},
		"impact": {
			"en": "Disconnections during long operations. No risk to the configuration, which on IOS is applied command by command.",
			"it": "Disconnessioni durante operazioni lunghe. Nessun rischio per la configurazione, che su IOS e' applicata comando per comando.",
		},
		"why": {
			"en": "An abandoned vty session stays authenticated and holds a line. With \u00abexec-timeout 0 0\u00bb it never expires: whoever finds that terminal inherits the privileges of the person who left it open.",
			"it": "Una sessione vty abbandonata resta autenticata e occupa una linea. Con \u00abexec-timeout 0 0\u00bb non scade mai: chi trova quel terminale ottiene i privilegi di chi l'ha lasciato aperto.",
		},
	},
	"check_ios_vty_transport_ssh": {
		"default": {
			"en": "\u00abtransport input all\u00bb on older releases, \u00abnone\u00bb on recent ones.",
			"it": "\u00abtransport input all\u00bb sulle versioni piu' vecchie, \u00abnone\u00bb su quelle recenti.",
		},
		"impact": {
			"en": "It requires SSH to be working already \u2014 domain set and RSA keys generated \u2014 otherwise the line becomes unusable. Verify that before closing Telnet.",
			"it": "Richiede che SSH sia gia' funzionante \u2014 dominio impostato e chiavi RSA generate \u2014 altrimenti la linea diventa inutilizzabile. Verificarlo prima di chiudere Telnet.",
		},
		"why": {
			"en": "Telnet sends the administrator's password in cleartext, one character at a time. On a vty line with no \u00abtransport input\u00bb the default applies, and on many releases that allows every available protocol: the missing directive is itself the problem.",
			"it": "Telnet trasmette la password dell'amministratore in chiaro, carattere per carattere. Su una linea vty senza \u00abtransport input\u00bb vale il default, che su molte versioni ammette ogni protocollo disponibile: l'assenza della direttiva e' quindi essa stessa il problema.",
		},
	},
	"check_linux_accept_redirects": {
		"impact": {
			"en": "Negligible on a network with managed static or dynamic routing: redirects are a stopgap for topologies with several gateways on one segment and a rough default route.",
			"it": "Trascurabile in una rete con routing statico o dinamico gestito: i redirect sono un ripiego per topologie con piu' gateway sullo stesso segmento e un default route approssimativo.",
		},
		"why": {
			"en": "An ICMP redirect tells the host \u00abfor that network, go through me\u00bb. Accepting it means anyone on the same segment can rewrite the routing table and put themselves in the middle of the traffic, without compromising anything and without leaving a trace in the host's logs.",
			"it": "Un ICMP redirect dice all'host \u00abper quella rete passa da me\u00bb. Accettarlo significa che chiunque sia sullo stesso segmento puo' riscrivere la tabella di routing e mettersi in mezzo al traffico, senza compromettere nulla e senza lasciare tracce nei log dell'host.",
		},
	},
	"check_linux_encrypt_method": {
		"default": {
			"en": "Ubuntu 24.04 uses yescrypt; older distributions SHA-512, and some minimal images declare nothing at all.",
			"it": "Ubuntu 24.04 usa yescrypt; distribuzioni piu' vecchie SHA-512, e alcune immagini minimali non dichiarano nulla.",
		},
		"impact": {
			"en": "The setting applies to passwords set from now on: existing hashes stay as they are until the user changes password.",
			"it": "Il parametro vale per le password impostate da qui in avanti: gli hash esistenti restano com'erano finche' l'utente non cambia password.",
		},
		"why": {
			"en": "It decides how expensive it is to try passwords against a stolen \u00ab/etc/shadow\u00bb. With a fast algorithm (MD5, DES) a billion-entry dictionary is exhausted in hours on a GPU; with yescrypt or SHA-512 the same work becomes impractical. It does not protect the file: it protects the passwords AFTER the file has left.",
			"it": "Determina quanto costa provare una password contro uno \u00ab/etc/shadow\u00bb rubato. Con un algoritmo veloce (MD5, DES) un dizionario da miliardi di voci si esaurisce in ore su una GPU; con yescrypt o SHA-512 lo stesso lavoro diventa impraticabile. Non protegge il file: protegge le password DOPO che il file e' uscito.",
		},
	},
	"check_linux_ip_forward": {
		"impact": {
			"en": "Do NOT apply it where forwarding is genuinely needed: container hosts (Docker, Kubernetes), VPN terminators, machines with virtual networks. Hence the benchmark's level 2: the setting depends on the host's role.",
			"it": "Da NON applicare dove l'inoltro serve davvero: host container (Docker, Kubernetes), terminatori VPN, macchine con reti virtuali. Di qui il livello 2 del benchmark: l'impostazione dipende dal ruolo dell'host.",
		},
		"why": {
			"en": "A host that forwards packets is a router, and a router attached to two segments joins them: traffic crosses over, bypassing the firewall that kept them apart. On a server with one leg in the DMZ and one in the LAN it is the shortcut that cancels the DMZ.",
			"it": "Un host che inoltra pacchetti e' un router, e un router collegato a due segmenti li unisce: il traffico passa aggirando il firewall che li teneva separati. Su un server con una gamba in DMZ e una in LAN e' la scorciatoia che annulla la DMZ.",
		},
	},
	"check_linux_log_martians": {
		"impact": {
			"en": "On a network with routing asymmetries the log can fill with legitimate lines: enable it together with adequate rotation and watch the first few days.",
			"it": "Su una rete con asimmetrie di routing il log puo' riempirsi di righe legittime: conviene attivarlo insieme a una rotazione adeguata e verificare i primi giorni.",
		},
		"why": {
			"en": "A \u00abmartian\u00bb packet carries a source address that cannot arrive on the interface it arrived on: the signature of spoofing or of a routing mistake. Without this setting the packet is dropped silently, and the fact that someone is forging addresses shows up nowhere.",
			"it": "Un pacchetto \u00abmarziano\u00bb ha un indirizzo di origine che non puo' arrivare dall'interfaccia da cui e' arrivato: e' la firma di uno spoofing o di un errore di routing. Senza questo parametro il pacchetto viene scartato in silenzio, e il fatto che qualcuno stia falsificando indirizzi non compare da nessuna parte.",
		},
	},
	"check_linux_pass_max_days": {
		"default": {
			"en": "\u00abPASS_MAX_DAYS 99999\u00bb \u2014 effectively never.",
			"it": "\u00abPASS_MAX_DAYS 99999\u00bb \u2014 in pratica mai.",
		},
		"impact": {
			"en": "Service accounts authenticating with a password stop working when it expires, usually at night. Move them to keys before applying the policy.",
			"it": "Gli account di servizio che si autenticano con password smettono di funzionare alla scadenza, spesso di notte. Vanno spostati su chiave prima di applicare la politica.",
		},
		"why": {
			"en": "A password that never expires stays valid long after it leaked, or after it left on a former employee's laptop. Expiry does not defend against an attack in progress: it caps how long an already-lost credential keeps working.",
			"it": "Una password che non scade mai resta valida anche dopo che e' finita in una fuga di dati o sul portatile di un ex dipendente. La scadenza non serve a difendersi da un attacco in corso: serve a mettere un tetto a quanto a lungo una credenziale gia' persa continua a funzionare.",
		},
	},
	"check_linux_pass_min_days": {
		"impact": {
			"en": "Someone who changes their password by mistake cannot undo it themselves and has to ask an administrator. For the same reason, after an assisted reset the parameter must be temporarily cleared on that user.",
			"it": "Chi cambia password per errore non puo' rimetterla subito a posto da solo e deve chiedere all'amministratore. Per lo stesso motivo, dopo un reset assistito il parametro va azzerato temporaneamente sull'utente.",
		},
		"why": {
			"en": "With no minimum wait, a user forced to change their password can change it repeatedly until the history is exhausted and then return to the old one: the expiry policy becomes a formality.",
			"it": "Senza un'attesa minima, un utente a cui viene imposto il cambio password puo' cambiarla piu' volte di fila fino a esaurire lo storico e tornare a quella di prima: la politica di scadenza diventa una formalita'.",
		},
	},
	"check_linux_pass_warn_age": {
		"impact": {
			"en": "None: it is just one more notice at login.",
			"it": "Nessuno: e' solo un avviso in piu' al login.",
		},
		"why": {
			"en": "With no warning, the password expires mid-session, usually at the worst moment. The practical effect is not a security risk but the shortcut that follows: predictable passwords chosen in a hurry, or requests to disable expiry.",
			"it": "Senza preavviso la password scade durante un accesso remoto, spesso quando serve di piu'. L'effetto pratico non e' un rischio di sicurezza ma la scorciatoia che ne segue: password prevedibili scelte di fretta, o richieste di disattivare la scadenza.",
		},
	},
	"check_linux_send_redirects": {
		"impact": {
			"en": "None on a host that does not route: with \u00abip_forward\u00bb already 0 it has nothing to redirect. On an intentional router, judge case by case.",
			"it": "Nessuno su un host che non instrada: se \u00abip_forward\u00bb e' gia' a 0 non ha nulla da ridirigere. Su un router intenzionale va valutato caso per caso.",
		},
		"why": {
			"en": "Emitting redirects tells whoever probes the host how the network behind it is laid out \u2014 which networks it knows and through which gateways. It is reconnaissance the host gives away with no authentication required.",
			"it": "Emettere redirect rivela a chi sonda l'host come e' fatta la rete dietro di lui \u2014 quali reti conosce e attraverso quali gateway. E' ricognizione che l'host regala senza che nessuno debba autenticarsi.",
		},
	},
	"check_linux_source_route": {
		"impact": {
			"en": "None: modern networks already block it at the border routers.",
			"it": "Nessuno: le reti moderne lo bloccano gia' sui router di confine.",
		},
		"why": {
			"en": "With source routing it is the SENDER who picks the packet's path: it can be steered around controls, and the reply can be sent back even from an address that is not the sender's. The mechanism has no legitimate uses left.",
			"it": "Con il source routing e' il MITTENTE a scegliere il percorso del pacchetto: puo' farlo passare per rotte che aggirano i controlli, e far tornare la risposta a se' anche da un indirizzo che non e' il suo. E' un meccanismo senza usi legittimi rimasti.",
		},
	},
	"check_linux_sshd_banner": {
		"impact": {
			"en": "No functional impact. The text must not disclose the operating system, its version or the host's role: that would be free reconnaissance.",
			"it": "Nessuno funzionale. Il testo non deve rivelare sistema operativo, versione o ruolo dell'host: sarebbe ricognizione regalata.",
		},
		"why": {
			"en": "It is not a technical control: it is the notice, shown BEFORE authentication, that access is restricted and monitored. In several jurisdictions its absence weakens action against an intruder, and nearly every regulatory framework requires it.",
			"it": "Non e' un controllo tecnico: e' la dichiarazione, mostrata PRIMA dell'autenticazione, che l'accesso e' riservato e monitorato. In diverse giurisdizioni la sua assenza indebolisce l'azione contro chi e' entrato senza titolo, ed e' richiesta da quasi tutti i quadri normativi.",
		},
	},
	"check_linux_sshd_client_alive": {
		"default": {
			"en": "\u00abClientAliveInterval\u00bb is 0, meaning no check at all.",
			"it": "\u00abClientAliveInterval\u00bb vale 0, cioe' nessun controllo.",
		},
		"impact": {
			"en": "Long, quiet sessions \u2014 a forgotten \u00abtail -f\u00bb, a compiler running for hours \u2014 get closed. Anyone needing them uses \u00abtmux\u00bb or \u00abscreen\u00bb, which survive a disconnect.",
			"it": "Le sessioni lunghe e silenziose \u2014 un \u00abtail -f\u00bb dimenticato, un compilatore che gira per ore \u2014 vengono chiuse. Chi ne ha bisogno usa \u00abtmux\u00bb o \u00abscreen\u00bb, che sopravvivono alla disconnessione.",
		},
		"why": {
			"en": "Without these two settings the server never closes an idle session: a console left open on an unattended workstation stays authenticated until something drops the network. This is what makes a screen lock real, not a duplicate of it.",
			"it": "Senza questi due parametri il server non chiude mai una sessione per inattivita': una console lasciata aperta su una postazione non presidiata resta autenticata finche' qualcosa non fa cadere la rete. E' il controllo che rende reale il blocco schermo, non un suo duplicato.",
		},
	},
	"check_linux_sshd_disable_forwarding": {
		"impact": {
			"en": "Legitimate uses of forwarding break: remote X11, port forwarding to a database, jump hosts. Apply it where the server is not a transit point \u2014 hence the benchmark's level 2.",
			"it": "Si rompono gli usi legittimi del forwarding: X11 remoto, port forwarding verso un database, i jump host. Da applicare dove il server non e' un punto di transito \u2014 di qui il livello 2 del benchmark.",
		},
		"why": {
			"en": "An SSH tunnel is a network path no firewall sees: whoever has a shell on the host can reach, from their own laptop, anything the host reaches. On a DMZ server that is exactly the bridge the DMZ is meant to prevent.",
			"it": "Un tunnel SSH e' una via di rete che nessun firewall vede: chi ha una shell sull'host puo' raggiungere, dal proprio portatile, qualunque cosa l'host raggiunga. Su un server in DMZ e' esattamente il ponte che la DMZ dovrebbe impedire.",
		},
	},
	"check_linux_sshd_hostbased_auth": {
		"impact": {
			"en": "Automation relying on \u00ab.shosts\u00bb/\u00abshosts.equiv\u00bb breaks. The replacement is a dedicated automation key with a forced command.",
			"it": "Si rompono gli automatismi che si appoggiano a \u00ab.shosts\u00bb/\u00abshosts.equiv\u00bb. La sostituzione e' una chiave dedicata per automazione, con comando forzato.",
		},
		"why": {
			"en": "Host-based authentication moves trust from the credential to the originating machine: whoever compromises one listed host gets into all the others without knowing a single password.",
			"it": "L'autenticazione basata sull'host sposta la fiducia dalla credenziale alla macchina di origine: chi compromette un host della lista entra su tutti gli altri senza sapere nessuna password.",
		},
	},
	"check_linux_sshd_ignore_rhosts": {
		"default": {
			"en": "OpenSSH already ignores them (\u00abIgnoreRhosts yes\u00bb).",
			"it": "OpenSSH li ignora gia' (\u00abIgnoreRhosts yes\u00bb).",
		},
		"impact": {
			"en": "None on a modern system: no current procedure still uses \u00ab.rhosts\u00bb files.",
			"it": "Nullo su un sistema moderno: nessuna procedura corrente usa piu' i file \u00ab.rhosts\u00bb.",
		},
		"why": {
			"en": "With \u00ab.rhosts\u00bb files honoured, it is the user who declares which hosts may connect to their account: a security decision taken outside the administrator's control, in a file the user can rewrite at will.",
			"it": "Con i file \u00ab.rhosts\u00bb onorati, e' l'utente stesso a dichiarare da quali host ci si puo' collegare al suo account: una decisione di sicurezza presa fuori dal controllo di chi amministra, in un file che l'utente puo' riscrivere quando vuole.",
		},
	},
	"check_linux_sshd_log_level": {
		"default": {
			"en": "OpenSSH uses INFO.",
			"it": "OpenSSH usa INFO.",
		},
		"impact": {
			"en": "VERBOSE increases log volume: on a host with many connections, account for it in log rotation.",
			"it": "VERBOSE aumenta il volume di log: su un host con molte connessioni va considerato nella rotazione.",
		},
		"why": {
			"en": "Below INFO the daemon stops recording which account logged in and from where: after an incident nothing can be reconstructed. VERBOSE adds the fingerprint of the key used, the only way to tell apart two logins by the same user with different keys.",
			"it": "Sotto INFO il demone non registra piu' quale account e' entrato e da dove: dopo un incidente non si ricostruisce nulla. VERBOSE aggiunge l'impronta della chiave usata, che e' l'unico modo di distinguere due accessi fatti con lo stesso utente ma chiavi diverse.",
		},
	},
	"check_linux_sshd_login_grace_time": {
		"default": {
			"en": "OpenSSH uses 120 seconds.",
			"it": "OpenSSH usa 120 secondi.",
		},
		"impact": {
			"en": "Over a very slow link, or with two-factor authentication requiring a manual step, 60 seconds may be tight: this is a value to tune, not to copy.",
			"it": "Su un collegamento molto lento, o con autenticazione a due fattori che richiede un'azione manuale, 60 secondi possono essere pochi: e' il valore da tarare, non da copiare.",
		},
		"why": {
			"en": "It is how long a connection can hold a slot without having authenticated yet. Keeping it high lets someone exhaust the few available slots by opening connections that never complete: a denial of service needing neither bandwidth nor credentials.",
			"it": "E' il tempo in cui una connessione occupa uno slot senza essersi ancora autenticata. Tenerlo alto permette di saturare i pochi slot disponibili aprendo connessioni che non completano mai: un blocco del servizio che non richiede banda ne' credenziali.",
		},
	},
	"check_linux_sshd_max_auth_tries": {
		"default": {
			"en": "OpenSSH grants 6 attempts.",
			"it": "OpenSSH concede 6 tentativi.",
		},
		"impact": {
			"en": "Anyone mistyping the password repeatedly has to reopen the connection. Watch out for clients with many keys in their agent: each offered key consumes an attempt.",
			"it": "Chi sbaglia password piu' volte di seguito deve riaprire la connessione. Attenzione ai client con molte chiavi in agent: ogni chiave offerta consuma un tentativo.",
		},
		"why": {
			"en": "Every connection grants N attempts, and connections can be reopened forever: the limit does not stop a brute-force attack, it makes it expensive and \u2014 above all \u2014 VISIBLE, because every failure past half the limit is logged.",
			"it": "Ogni connessione concede N tentativi, e le connessioni si possono riaprire all'infinito: il limite non ferma un attacco a forza bruta, lo rende costoso e \u2014 soprattutto \u2014 lo rende VISIBILE, perche' ogni fallimento oltre la meta' del limite viene registrato.",
		},
	},
	"check_linux_sshd_permit_empty_passwords": {
		"default": {
			"en": "OpenSSH already keeps it at \u00abno\u00bb.",
			"it": "OpenSSH lo tiene gia' a \u00abno\u00bb.",
		},
		"impact": {
			"en": "None: password-less access is not a legitimate use case. If something breaks, that something was the vulnerability.",
			"it": "Nessuno: un accesso senza password non e' un caso d'uso legittimo. Se qualcosa smette di funzionare, quel qualcosa era la vulnerabilita'.",
		},
		"why": {
			"en": "An account with an empty password is an account with no authentication at all. It happens by accident on service users created by scripts, and nobody notices until someone else finds it.",
			"it": "Un account con password vuota e' un account senza autenticazione. Capita per errore su utenti di servizio creati da script, e nessuno se ne accorge finche' non lo trova qualcun altro.",
		},
	},
	"check_linux_sshd_permit_root_login": {
		"default": {
			"en": "OpenSSH uses \u00abprohibit-password\u00bb: root cannot use a password but can still use a key. The benchmark asks for \u00abno\u00bb.",
			"it": "OpenSSH usa \u00abprohibit-password\u00bb: root non entra con password ma entra con chiave. Il benchmark chiede \u00abno\u00bb.",
		},
		"impact": {
			"en": "Anyone administering by logging straight in as root must switch to a named account with \u00absudo\u00bb. Check backup jobs and scripts that connect as root first, and that at least one unprivileged account can already get in.",
			"it": "Chi amministra collegandosi direttamente come root deve passare a un account nominale con \u00absudo\u00bb. Verificare prima gli script e i job di backup che si collegano come root, e che almeno un account non privilegiato possa gia' entrare.",
		},
		"why": {
			"en": "Root is not an account, it is the end state of every attack: allowing it at the SSH prompt removes the middle step (log in as a user, then escalate) and makes one guessed password enough. A direct root login also loses WHO it was: the logs say \u00abroot\u00bb, not the person.",
			"it": "Root non e' un account, e' l'esito finale di ogni attacco: ammetterlo al login SSH toglie il passaggio intermedio (entrare come utente, poi scalare) e rende una sola password indovinata sufficiente. In piu' un accesso diretto come root non lascia traccia di CHI era: nei log c'e' \u00abroot\u00bb, non la persona.",
		},
	},
	"check_linux_tcp_syncookies": {
		"default": {
			"en": "Recent kernels keep it on already, but an inherited tuning file may have turned it off.",
			"it": "I kernel recenti lo tengono gia' attivo, ma un file di tuning ereditato puo' averlo spento.",
		},
		"impact": {
			"en": "Under attack some negotiated TCP options (window scaling, timestamps) can be lost, costing performance on the connections accepted via cookies. Outside an attack the mechanism never kicks in.",
			"it": "Sotto attacco alcune opzioni TCP negoziate (window scaling, timestamp) possono andare perse, con un calo di prestazioni sulle connessioni accettate via cookie. Fuori attacco il meccanismo non entra in gioco.",
		},
		"why": {
			"en": "The half-open connection queue is small and fills with very little traffic: without syncookies a few thousand SYNs per second \u2014 one domestic line \u2014 make a service unreachable. With them the server keeps no state until the connection completes, and the queue never fills.",
			"it": "La coda delle connessioni mezze aperte e' piccola e si riempie con pochissimo traffico: senza syncookies bastano poche migliaia di SYN al secondo \u2014 una singola linea domestica \u2014 per rendere irraggiungibile un servizio. Con essi il server non tiene stato finche' la connessione non e' completa, e la coda non si riempie.",
		},
	},
	"check_linux_tmp_mount_options": {
		"default": {
			"en": "On many installations \u00ab/tmp\u00bb is not a separate partition and no option applies at all.",
			"it": "Su molte installazioni \u00ab/tmp\u00bb non e' una partizione separata e nessuna opzione si applica.",
		},
		"impact": {
			"en": "\u00abnoexec\u00bb breaks installers and build tools that extract and execute inside \u00ab/tmp\u00bb \u2014 common with third-party packages and with some just-in-time runtimes. Try it on a test host first.",
			"it": "\u00abnoexec\u00bb rompe gli installer e i compilatori che estraggono ed eseguono in \u00ab/tmp\u00bb \u2014 capita con pacchetti di terze parti e con alcuni runtime che compilano a caldo. Da verificare prima su un host di prova.",
		},
		"why": {
			"en": "\u00ab/tmp\u00bb is world-writable: it is where the payload of almost every exploit lands. With \u00abnoexec\u00bb the downloaded file will not run, with \u00abnosuid\u00bb a setuid binary dropped there grants nothing, with \u00abnodev\u00bb no device node can be forged to read the raw disk. It does not prevent the intrusion: it removes its next step.",
			"it": "\u00ab/tmp\u00bb e' scrivibile da chiunque: e' il posto dove atterra il payload di quasi ogni exploit. Con \u00abnoexec\u00bb il file scaricato non parte, con \u00abnosuid\u00bb un binario setuid depositato li' non concede privilegi, con \u00abnodev\u00bb non si puo' fabbricare un device per leggere il disco crudo. Non impedisce l'intrusione: le toglie il passo successivo.",
		},
	},
	"check_linux_var_mount_options": {
		"impact": {
			"en": "Negligible: no normal service needs device nodes or setuid binaries under \u00ab/var\u00bb. \u00abnoexec\u00bb however must NOT be added \u2014 several package managers run scripts from there.",
			"it": "Trascurabile: nessun servizio normale ha bisogno di device o binari setuid dentro \u00ab/var\u00bb. \u00abnoexec\u00bb invece NON va messo \u2014 diversi gestori di pacchetti eseguono script da li'.",
		},
		"why": {
			"en": "\u00ab/var\u00bb holds data written by services \u2014 mail queues, caches, uploads \u2014 that is, content arriving from outside. \u00abnodev\u00bb and \u00abnosuid\u00bb stop a file dropped there from becoming a device node or a privileged executable.",
			"it": "\u00ab/var\u00bb contiene dati scritti dai servizi \u2014 code di posta, cache, upload \u2014 cioe' contenuto che arriva dall'esterno. \u00abnodev\u00bb e \u00abnosuid\u00bb impediscono che un file depositato li' diventi un device o un eseguibile privilegiato.",
		},
	},
	"check_local_in_policy": {
		"default": {
			"en": "no local-in policy.",
			"it": "nessuna policy local-in.",
		},
		"impact": {
			"en": "A badly written local-in policy locks the administrator out, and it is not editable from the GUI on every version. Have console access ready before applying it.",
			"it": "Una local-in scritta male chiude fuori l'amministratore e non e' modificabile da GUI su tutte le versioni. Prepararsi l'accesso da console prima di applicarla.",
		},
		"why": {
			"en": "\u00aballowaccess\u00bb decides WHICH services the device exposes on an interface, not TO WHOM. \u00ablocal-in\u00bb policies are the only way to filter, by source, traffic aimed at the device itself \u2014 the GUI, SSH, the VPN portal.",
			"it": "\u00aballowaccess\u00bb decide QUALI servizi l'apparato espone su un'interfaccia, non A CHI. Le policy \u00ablocal-in\u00bb sono l'unico modo di filtrare per sorgente il traffico diretto all'apparato stesso \u2014 la GUI, SSH, il portale VPN.",
		},
	},
	"check_log_local_disk": {
		"impact": {
			"en": "On entry-level models continuous writing wears the flash. Tune retention rather than turning it off.",
			"it": "Su modelli entry-level la scrittura continua consuma la memoria flash. Valutare la ritenzione invece di disattivare.",
		},
		"why": {
			"en": "The local disk is the safety net for when the remote collector is unreachable \u2014 which is precisely during a network failure or an attack, the moments when logs matter. Without it, that window stays empty forever.",
			"it": "Il disco locale e' la rete di sicurezza quando il collector remoto e' irraggiungibile \u2014 cioe' proprio durante un guasto di rete o un attacco, che sono i momenti in cui i log servono. Senza, quella finestra resta vuota per sempre.",
		},
	},
	"check_login_banners": {
		"default": {
			"en": "disable.",
			"it": "disable.",
		},
		"impact": {
			"en": "None on traffic. Have the wording approved by legal rather than improvising it.",
			"it": "Nessuno sul traffico. Far approvare il testo dall'ufficio legale invece di improvvisarlo.",
		},
		"why": {
			"en": "The banner prevents nothing technically: its purpose is legal. In many jurisdictions the absence of an explicit notice weakens action against unauthorised access, since the intruder can claim they were never warned.",
			"it": "Il banner non impedisce nulla sul piano tecnico: serve sul piano legale. In molte giurisdizioni l'assenza di un'avvertenza esplicita indebolisce l'azione contro chi accede senza titolo, che puo' sostenere di non essere stato avvisato.",
		},
	},
	"check_management_protocols": {
		"default": {
			"en": "On a fresh interface \u00aballowaccess\u00bb is empty; canned profiles often add ping and https.",
			"it": "Su un'interfaccia nuova \u00aballowaccess\u00bb e' vuoto; i profili preconfezionati aggiungono spesso ping e https.",
		},
		"impact": {
			"en": "Anyone still administering over Telnet or HTTP loses access until they switch to SSH/HTTPS. Check first that no automation scripts rely on those protocols.",
			"it": "Chi amministra ancora via Telnet o HTTP perde l'accesso finche' non passa a SSH/HTTPS. Verificare prima che gli script di automazione non usino quei protocolli.",
		},
		"why": {
			"en": "Telnet and HTTP carry credentials and session data in cleartext: anyone on the same segment, or on any hop in between, reads the administrator password as typed. On an externally facing interface that amounts to publishing it.",
			"it": "Telnet e HTTP trasmettono credenziali e sessione in chiaro: chi e' sullo stesso segmento, o su un qualunque tratto attraversato, legge la password dell'amministratore cosi' com'e'. Su un'interfaccia esposta verso l'esterno equivale a pubblicarla.",
		},
	},
	"check_ntp": {
		"default": {
			"en": "synchronisation enabled towards the FortiGuard NTP servers.",
			"it": "sincronizzazione attiva verso i server NTP di FortiGuard.",
		},
		"impact": {
			"en": "The first sync can move the clock a long way and produce a jump in the logs. Better in a maintenance window if the device terminates VPN sessions.",
			"it": "Il primo allineamento puo' spostare l'orologio di parecchio e produrre un salto nei log. Meglio in finestra di manutenzione se l'apparato termina sessioni VPN.",
		},
		"why": {
			"en": "A drifting clock invalidates certificate validation, time-based tokens and cross-device correlation. In an investigation, unsynchronised timestamps make it impossible to establish what happened first.",
			"it": "Un orologio alla deriva invalida la verifica dei certificati, i token a tempo e la correlazione fra apparati. In un'indagine, timestamp non sincronizzati rendono impossibile stabilire cosa e' successo prima.",
		},
	},
	"check_password_policy_strength": {
		"default": {
			"en": "status disable.",
			"it": "status disable.",
		},
		"impact": {
			"en": "The policy applies at the next change, not retroactively: weak passwords already set stay valid until they expire. Turn \u00abexpire-status\u00bb on as well.",
			"it": "La policy si applica al cambio successivo, non retroattivamente: le password deboli gia' impostate restano valide finche' non scadono. Attivare anche \u00abexpire-status\u00bb.",
		},
		"why": {
			"en": "Firewall credentials are worth the entire network behind them. A policy enforcing length and variety does not make a password good, but it rules out the ones a dictionary attack solves in minutes.",
			"it": "Le credenziali di un firewall valgono l'intera rete che protegge. Una policy che impone lunghezza e varieta' non rende una password buona, ma esclude quelle che un attacco a dizionario risolve in pochi minuti.",
		},
	},
	"check_policy_comments": {
		"impact": {
			"en": "None.",
			"it": "Nessuno.",
		},
		"why": {
			"en": "Not a security control but the condition for the others to stay workable: a rule with no recorded reason never gets removed, because nobody knows what it would break. Rules pile up and the access policy becomes unreadable.",
			"it": "Non e' un controllo di sicurezza ma la condizione perche' gli altri restino applicabili: una regola senza motivazione registrata non viene mai rimossa, perche' nessuno sa cosa romperebbe. Le regole si accumulano e il criterio di accesso diventa illeggibile.",
		},
	},
	"check_policy_logging": {
		"default": {
			"en": "disabled: a new policy logs nothing, and neither does the final implicit deny.",
			"it": "disabilitato: una policy nuova non registra nulla, e nemmeno il deny implicito finale lo fa.",
		},
		"impact": {
			"en": "It increases log volume, and disk and collector load, considerably. On very high-traffic rules consider \u00ablogtraffic utm\u00bb as a compromise.",
			"it": "Aumenta molto il volume dei log e il carico su disco e collector. Su regole ad altissimo traffico valutare \u00ablogtraffic utm\u00bb come compromesso.",
		},
		"why": {
			"en": "Without \u00ablogtraffic all\u00bb, FortiOS logs only the sessions touched by a security profile: plainly permitted traffic leaves no trace. That is exactly what you need to look at after an incident, to establish what left the network.",
			"it": "Senza \u00ablogtraffic all\u00bb FortiOS registra solo le sessioni toccate da un security profile: il traffico semplicemente consentito non lascia traccia. E' proprio quello che serve guardare dopo un incidente, per stabilire cosa e' uscito.",
		},
	},
	"check_policy_security_profiles": {
		"impact": {
			"en": "Inspection costs CPU and can reduce throughput; SSL inspection in particular breaks applications that use certificate pinning. Introduce it gradually.",
			"it": "L'ispezione consuma CPU e puo' ridurre il throughput; l'ispezione SSL in particolare rompe le applicazioni che usano certificate pinning. Introdurla per gradi.",
		},
		"why": {
			"en": "An Internet-bound rule with no inspection profiles lets malware, command-and-control and exfiltration through unexamined: the device behaves like a NAT router. The licence to inspect is already there, it is simply not applied to that rule.",
			"it": "Una regola verso Internet senza profili di ispezione lascia passare malware, comando e controllo ed esfiltrazione senza guardarli: l'apparato si comporta come un router con NAT. La licenza per ispezionare c'e' gia', semplicemente non e' applicata a quella regola.",
		},
	},
	"check_snmp_community": {
		"impact": {
			"en": "Every monitoring system polling the device has to be reconfigured with the new community, otherwise the graphs stop with no obvious error.",
			"it": "Ogni sistema di monitoraggio che interroga l'apparato va riconfigurato con la nuova community, altrimenti i grafici si fermano senza un errore evidente.",
		},
		"why": {
			"en": "\u00abpublic\u00bb and \u00abprivate\u00bb are the first two values any scanning tool tries. A default community is a known credential that exposes the device's whole configuration, routing and interface tables.",
			"it": "\u00abpublic\u00bb e \u00abprivate\u00bb sono i primi due valori che qualunque strumento di scansione prova. Una community di default e' una credenziale nota che espone l'intera tabella di configurazione, di routing e di interfacce dell'apparato.",
		},
	},
	"check_snmp_v3_only": {
		"impact": {
			"en": "Every monitoring system has to move to SNMPv3 with a user, an authentication key and a privacy key. Not every legacy tool supports it: check first.",
			"it": "Ogni sistema di monitoraggio va migrato a SNMPv3 con utente, chiave di autenticazione e chiave di cifratura. Non tutti gli strumenti datati lo supportano: verificarlo prima.",
		},
		"why": {
			"en": "SNMP v1 and v2c have no authentication: the community is a cleartext password inside every packet, repeated at every poll. Capture it once and you can read the device's entire state from then on. SNMPv3 authenticates and encrypts.",
			"it": "SNMP v1 e v2c non hanno autenticazione: la community e' una password in chiaro dentro ogni pacchetto, ripetuta a ogni polling. Chi la intercetta una volta legge da quel momento l'intero stato dell'apparato. SNMPv3 autentica e cifra.",
		},
	},
	"check_sslvpn_source_restriction": {
		"impact": {
			"en": "Only workable if remote users have predictable addresses, or by country. With travelling users it is often impractical: there, the equivalent control is multi-factor authentication.",
			"it": "Applicabile solo se gli utenti remoti hanno indirizzi prevedibili, o per paese. Con utenti in mobilita' e' spesso impraticabile: in quel caso la misura equivalente e' l'autenticazione a piu' fattori.",
		},
		"why": {
			"en": "A VPN portal reachable from the whole world faces constant credential stuffing, and some of the most serious FortiOS vulnerabilities are exploitable pre-authentication. Restricting sources shrinks the surface even against an unpatched exploit.",
			"it": "Un portale VPN raggiungibile dal mondo intero e' sottoposto a credential stuffing continuo, e alcune delle vulnerabilita' piu' gravi di FortiOS si sfruttano prima dell'autenticazione. Restringere le sorgenti riduce la superficie anche contro un exploit non ancora corretto.",
		},
	},
	"check_sslvpn_tls": {
		"default": {
			"en": "tls1-2 as the minimum on FortiOS 7.4: the check is already satisfied unless someone lowered it.",
			"it": "tls1-2 come minimo su FortiOS 7.4: il controllo e' gia' soddisfatto salvo che qualcuno l'abbia abbassato.",
		},
		"impact": {
			"en": "Older VPN clients may fail to connect. Check the FortiClient version in use before applying it.",
			"it": "Client VPN datati possono non connettersi piu'. Verificare la versione di FortiClient in uso prima di applicarlo.",
		},
		"why": {
			"en": "The SSL-VPN portal is by definition exposed to the Internet, and remote users' credentials travel across it. It is the place in the configuration where a deprecated TLS version costs the most.",
			"it": "Il portale SSL-VPN e' per definizione esposto su Internet e vi transitano le credenziali degli utenti remoti. E' il punto della configurazione dove una versione di TLS deprecata pesa di piu'.",
		},
	},
	"check_static_key_ciphers": {
		"default": {
			"en": "enable \u2014 static-key ciphers are allowed out of the box.",
			"it": "enable \u2014 i cifrari a chiave statica sono ammessi di fabbrica.",
		},
		"impact": {
			"en": "Negligible: every modern client supports ephemeral exchange.",
			"it": "Trascurabile: ogni client moderno supporta lo scambio effimero.",
		},
		"why": {
			"en": "Static-key ciphers give no forward secrecy: whoever records encrypted traffic today and obtains the server's private key tomorrow can retroactively decrypt the whole archive. With ephemeral exchange, compromising the key does not unlock the past.",
			"it": "I cifrari a chiave statica non danno forward secrecy: chi registra oggi il traffico cifrato e ottiene domani la chiave privata del server puo' decifrare retroattivamente tutto l'archivio. Con lo scambio effimero, la compromissione della chiave non apre il passato.",
		},
	},
	"check_strong_crypto": {
		"default": {
			"en": "enable \u2014 but on devices upgraded from very old releases it can end up disabled.",
			"it": "enable \u2014 ma su apparati aggiornati da versioni molto vecchie puo' risultare disabilitato.",
		},
		"impact": {
			"en": "Very old SSH clients and monitoring tools may fail to negotiate. Check collectors and backup systems before applying it in production.",
			"it": "Client SSH e tool di monitoraggio molto datati possono non negoziare piu'. Da verificare su collector e sistemi di backup prima di applicarlo in produzione.",
		},
		"why": {
			"en": "Without \u00abstrong-crypto\u00bb the device keeps offering legacy ciphers and hashes (3DES, RC4, MD5, SHA-1) on its own SSL/SSH sessions: effective security is that of the weakest cipher a client can negotiate, not the strongest available.",
			"it": "Senza \u00abstrong-crypto\u00bb l'apparato continua a offrire cifrari e hash legacy (3DES, RC4, MD5, SHA-1) nelle proprie sessioni SSL/SSH: la sicurezza effettiva e' quella del cifrario piu' debole che il client riesce a negoziare, non del piu' forte disponibile.",
		},
	},
	"check_syslog": {
		"impact": {
			"en": "Volume: a busy firewall easily produces tens of GB per day. Size the collector and the retention before turning forwarding on.",
			"it": "Volume: un firewall carico genera facilmente decine di GB al giorno. Dimensionare il collector e la ritenzione prima di attivare l'inoltro.",
		},
		"why": {
			"en": "Logs that stay on the device alone are exactly the ones an attacker wipes first, and they vanish anyway at reboot or rotation. With no remote copy there is no investigation possible, and no evidence of compliance either.",
			"it": "I log che restano solo sull'apparato sono esattamente quelli che un attaccante cancella per primo, e spariscono comunque al riavvio o alla rotazione. Senza copia remota non c'e' indagine possibile, e nemmeno prova di conformita'.",
		},
	},
	"check_syslog_encrypted": {
		"default": {
			"en": "disabled.",
			"it": "disabilitato.",
		},
		"impact": {
			"en": "The collector has to accept syslog over TLS and present a valid certificate. Not every syslog server does.",
			"it": "Il collector deve accettare syslog su TLS e presentare un certificato valido. Non tutti i server syslog lo fanno.",
		},
		"why": {
			"en": "The syslog stream carries addresses, usernames, destinations and actions for every session: it is a map of the network and of who works on it. In cleartext, anyone on the path to the collector reads it.",
			"it": "Il flusso syslog contiene indirizzi, nomi utente, destinazioni e azioni di ogni sessione: e' una mappa della rete e di chi ci lavora. In chiaro, chiunque si trovi sul percorso verso il collector la legge.",
		},
	},
	"check_timezone": {
		"default": {
			"en": "(GMT-8:00) Pacific Time.",
			"it": "(GMT-8:00) Pacific Time.",
		},
		"impact": {
			"en": "Logs already recorded keep the old reference: note when the change happened, otherwise the archive holds an unexplained discontinuity.",
			"it": "I log gia' registrati mantengono il vecchio riferimento: annotare il momento del cambio, altrimenti l'archivio contiene una discontinuita' inspiegata.",
		},
		"why": {
			"en": "With the wrong time zone every event is recorded at a time that does not match reality: correlation with the other devices breaks, and in an investigation the sequence of events comes out distorted exactly when it matters.",
			"it": "Se il fuso e' sbagliato ogni evento e' registrato con un'ora che non corrisponde a quella reale: la correlazione con gli altri apparati salta, e in un'indagine la sequenza dei fatti risulta alterata proprio quando conta.",
		},
	},
	"check_tls_version": {
		"default": {
			"en": "Varies with the FortiOS release: recent versions start at TLS 1.2, older ones still accept 1.0.",
			"it": "Varia con la versione di FortiOS: le release recenti partono da TLS 1.2, le piu' vecchie accettano ancora 1.0.",
		},
		"impact": {
			"en": "Very old browsers and clients can no longer reach the GUI. In practice this only affects out-of-support machines.",
			"it": "Browser e client molto vecchi non riescono piu' a collegarsi alla GUI. In pratica riguarda solo postazioni fuori supporto.",
		},
		"why": {
			"en": "TLS 1.0 and 1.1 rely on constructions (CBC with MAC-then-encrypt, SHA-1 in signatures) with practical attacks against them, and are retired by PCI-DSS and the main regulations. Allowing them means an attacker can force the negotiation down to the weakest accepted version.",
			"it": "TLS 1.0 e 1.1 usano costruzioni (CBC con MAC-then-encrypt, SHA-1 nelle firme) per cui esistono attacchi pratici, e sono ritirati da PCI-DSS e dalle principali normative. Ammetterli significa che un attaccante puo' forzare la negoziazione verso la versione piu' debole accettata.",
		},
	},
	"check_vendor_defaults": {
		"impact": {
			"en": "Create the replacement administrative account and verify it works BEFORE removing \u00abadmin\u00bb: that order is what stops you ending up with no administrator at all.",
			"it": "Creare il nuovo account amministrativo e verificarne l'accesso PRIMA di rimuovere \u00abadmin\u00bb: e' l'ordine che evita di restare senza alcun amministratore.",
		},
		"why": {
			"en": "The factory \u00abadmin\u00bb account is the first name anyone tries, and since nobody ever created it, it often escapes periodic access reviews. With no password policy enforced, nothing stops it from getting a trivial password.",
			"it": "L'account \u00abadmin\u00bb di fabbrica e' il primo nome che viene provato, e non essendo mai stato creato da nessuno spesso non compare nelle revisioni periodiche degli accessi. Senza password policy attiva, nulla impedisce di assegnargli una password banale.",
		},
	},
}

func GuidanceFor(checkName, lang string) map[string]string {
	code := NormalizeLang(lang)
	entry, ok := Guidance[checkName]
	if !ok {
		return map[string]string{}
	}
	res := make(map[string]string)
	for field, langMap := range entry {
		txt := langMap[code]
		if txt == "" {
			txt = langMap["it"]
		}
		res[field] = txt
	}
	return res
}
