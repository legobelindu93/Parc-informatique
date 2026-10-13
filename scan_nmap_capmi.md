# Scan Nmap — capmi.fr (185.177.60.169)

**Date :** 2026-06-23 17:44 CEST  
**Commande :** `nmap -sV -sC -p 21,22,80,443,2000,5060 capmi.fr`  
**Hébergeur :** Infomaniak

---

## Résumé des ports

| Port | État  | Service           | Version / Détail |
|------|-------|-------------------|------------------|
| 21   | open  | FTP               | ProFTPD |
| 22   | open  | SSH               | OpenSSH 8.4p1 Debian 5+deb11u7 (protocol 2.0) |
| 80   | open  | HTTP              | Apache (403 Forbidden) |
| 443  | open  | HTTPS             | Apache (403 Forbidden) |
| 2000 | open  | cisco-sccp?       | Non identifié |
| 5060 | open  | sip?              | Non identifié |

---

## Détail par port

### Port 21 — FTP (ProFTPD)

- **Certificat TLS :**
  - Sujet : `*.ftp.infomaniak.com`
  - SAN : `*.ftp.infomaniak.com`, `ftp.infomaniak.com`
  - Valide : 2025-08-29 → 2026-09-11

### Port 22 — SSH (OpenSSH 8.4p1)

- **Empreintes :**
  - `3072 SHA256:8b254e5fb45b8f89723abe5a0e91a218` (RSA)
  - `256 SHA256:bb501ee113f24c7b4cc0e440d89ab7e2` (ECDSA)
  - `256 SHA256:944fdcb60ffb23beb7708eb5071234cf` (ED25519)

### Port 80 — HTTP (Apache)

- **Réponse :** 403 Forbidden
- **Headers :** `server: Apache`, `upgrade: h2`
- **Titre :** *Site doesn't have a title*

### Port 443 — HTTPS (Apache)

- **Certificat SSL :**
  - Sujet : `capmi.fr`
  - SAN : `capmi.fr`
  - Valide : 2026-05-24 → 2026-08-22
- **Réponse :** 403 Forbidden
- **Headers :** `server: Apache`, `strict-transport-security: max-age=16000000`, `upgrade: h2`
- **Titre :** *Site doesn't have a title*

### Port 2000 — cisco-sccp ?

Service non identifié par nmap.

### Port 5060 — sip ?

Service non identifié par nmap.

---

## Informations générales

| Champ | Valeur |
|-------|--------|
| IP | 185.177.60.169 |
| Hostname | capmi.fr |
| OS identifié | Unix / Linux |
| CPE | `cpe:/o:linux:linux_kernel` |
| Hébergeur | Infomaniak (via email `null@infomaniak.ch` dans les pages d'erreur) |

---

## Notes

- Les ports 80 et 443 retournent **403 Forbidden** — l'accès direct est bloqué, probablement un reverse proxy / firewall applicatif Infomaniak.
- HSTS activé sur le HTTPS (`max-age=16000000` soit ~185 jours).
- Le FTP pointe vers l'infrastructure générique Infomaniak (`*.ftp.infomaniak.com`), pas vers une instance dédiée.
- 2 services non identifiés sur les ports 2000 et 5060.
