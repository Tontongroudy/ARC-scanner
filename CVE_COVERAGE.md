# Couverture CVE — ARC Scanner

## Comment fonctionne la détection

ARC Scanner utilise deux outils complémentaires :

- **Nmap + script `vulners`** : détecte les services et versions sur la cible, puis interroge la base [vulners.com](https://vulners.com) pour lister les CVEs associées à ces versions. La liste est dynamique — elle dépend des services trouvés sur la cible.
- **Nuclei** (`-severity critical,high,medium`) : exécute des templates de détection actifs contre la cible. Couvre des milliers de CVEs connues via le dépôt [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates).

> La liste exacte des CVEs détectées varie selon les services actifs sur la cible et la version des templates Nuclei installés.

---

## Catégories couvertes

| Catégorie | Exemples de technologies ciblées |
|-----------|----------------------------------|
| Serveurs web | Apache, Nginx, IIS, Tomcat, LiteSpeed |
| Frameworks | Spring, Laravel, Django, Struts |
| CMS | WordPress, Drupal, Joomla, Magento |
| Bases de données | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| Messagerie | Exchange, Zimbra, Roundcube |
| VPN / Accès distant | Citrix, Pulse Secure, Fortinet, Cisco |
| Virtualisation | VMware vCenter, ESXi |
| Services réseau | SMB, RDP, FTP, SSH, Telnet |
| Panneaux d'administration | cPanel, Plesk, Webmin, phpMyAdmin |
| Conteneurs / DevOps | Docker API, Kubernetes, Jenkins, GitLab |

---

## CVEs critiques notables détectées par Nuclei

### Exécution de code à distance (RCE)

| CVE | Description | Sévérité |
|-----|-------------|----------|
| CVE-2021-44228 | Log4Shell — Apache Log4j | Critique |
| CVE-2022-22965 | Spring4Shell — Spring Framework | Critique |
| CVE-2021-26855 | ProxyLogon — Microsoft Exchange | Critique |
| CVE-2021-34473 | ProxyShell — Microsoft Exchange | Critique |
| CVE-2020-14882 | Oracle WebLogic RCE | Critique |
| CVE-2019-19781 | Citrix ADC / Gateway RCE | Critique |
| CVE-2021-21985 | VMware vCenter RCE | Critique |
| CVE-2022-1388  | F5 BIG-IP iControl RCE | Critique |
| CVE-2021-41773 | Apache HTTP Server Path Traversal / RCE | Critique |
| CVE-2018-13379 | Fortinet FortiOS Path Traversal | Critique |

### Divulgation d'informations

| CVE | Description | Sévérité |
|-----|-------------|----------|
| CVE-2021-22986 | F5 BIG-IP iControl info leak | Critique |
| CVE-2019-11580 | Atlassian Crowd RCE + info leak | Critique |
| CVE-2020-1472   | Zerologon — Netlogon privilege escalation | Critique |
| CVE-2021-26084 | Atlassian Confluence OGNL injection | Critique |
| CVE-2017-9841  | PHPUnit RCE via eval-stdin | Critique |

### Injection SQL

| CVE | Description | Sévérité |
|-----|-------------|----------|
| CVE-2022-21500 | Oracle E-Business Suite SQLi | Haute |
| CVE-2019-9978  | Social Warfare WordPress SQLi | Haute |
| CVE-2021-24762 | Perfect Survey WordPress SQLi | Haute |

### Protocoles réseau (via Nmap + vulners)

| CVE | Description | Sévérité |
|-----|-------------|----------|
| CVE-2017-0144  | EternalBlue — SMBv1 | Critique |
| CVE-2019-0708  | BlueKeep — RDP | Critique |
| CVE-2021-36942 | PetitPotam — NTLM relay | Haute |
| CVE-2020-0796  | SMBGhost — SMBv3 | Critique |
| CVE-2018-10933 | libssh authentication bypass | Critique |

### Panneaux d'administration exposés

| CVE | Description | Sévérité |
|-----|-------------|----------|
| CVE-2022-0847  | Dirty Pipe — Linux kernel | Haute |
| CVE-2021-3156  | Sudo Baron Samedit | Haute |
| CVE-2020-11651 | SaltStack API auth bypass | Critique |
| CVE-2019-16278 | Nostromo httpd RCE | Critique |

---

## Limites

- **NAT / réseau interne** : ARC Scanner scanne depuis le serveur. Seules les ressources **exposées sur internet** sont atteignables. Les appareils derrière un routeur (192.168.x.x, 10.x.x.x) ne sont pas accessibles.
- **Faux négatifs** : un service peut être vulnérable sans qu'un template Nuclei existe pour cette CVE spécifique.
- **Faux positifs** : certains templates détectent la présence d'un service sans confirmer l'exploitabilité réelle.
- **Templates Nuclei** : la couverture s'améliore à chaque mise à jour (`nuclei -update-templates`). Pense à mettre à jour régulièrement.

---

## Mettre à jour les templates Nuclei

```bash
nuclei -update-templates
```

Cela télécharge les derniers templates depuis le dépôt officiel et élargit la couverture CVE automatiquement.
