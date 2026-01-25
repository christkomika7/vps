#!/bin/bash
#
# Script d'Installation Automatique de Sécurité VPS
# Compatible avec Tailscale
# 
# ATTENTION: Lisez tout le script avant de l'exécuter!
# Configurez les variables ci-dessous avant de lancer
#

set -e  # Arrêter en cas d'erreur

# ============================================
# CONFIGURATION - À MODIFIER SELON VOS BESOINS
# ============================================

# Informations utilisateur
NEW_USER="votre_utilisateur"          # Votre nom d'utilisateur
USER_EMAIL="votre_email@example.com"  # Votre email pour les alertes

# Configuration SSH
SSH_PORT="2222"                       # Port SSH personnalisé

# Votre clé publique SSH (optionnel - laissez vide si déjà configurée)
SSH_PUBLIC_KEY=""

# IP Tailscale (laissez vide, sera détecté automatiquement)
TAILSCALE_IP=""

# ============================================
# COULEURS POUR L'AFFICHAGE
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================
# FONCTIONS UTILITAIRES
# ============================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

# ============================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ============================================

print_header "VÉRIFICATIONS PRÉLIMINAIRES"

check_root

# Vérifier si Tailscale est installé
if ! command -v tailscale &> /dev/null; then
    print_warning "Tailscale n'est pas installé. Installation en cours..."
    curl -fsSL https://tailscale.com/install.sh | sh
    print_success "Tailscale installé. Veuillez l'activer avec 'sudo tailscale up' avant de continuer"
    exit 1
fi

# Vérifier si Tailscale est actif
if ! tailscale status &> /dev/null; then
    print_error "Tailscale n'est pas actif. Exécutez 'sudo tailscale up' puis relancez ce script"
    exit 1
fi

# Détecter l'IP Tailscale
if [ -z "$TAILSCALE_IP" ]; then
    TAILSCALE_IP=$(tailscale ip -4)
    print_success "IP Tailscale détectée: $TAILSCALE_IP"
fi

# Sauvegarder l'IP publique
PUBLIC_IP=$(curl -s ifconfig.me)
print_success "IP publique: $PUBLIC_IP"

# ============================================
# 1. MISE À JOUR DU SYSTÈME
# ============================================

print_header "1. MISE À JOUR DU SYSTÈME"

apt update
apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt autoclean

print_success "Système mis à jour"

# ============================================
# 2. CRÉATION UTILISATEUR NON-ROOT
# ============================================

print_header "2. CONFIGURATION UTILISATEUR"

if id "$NEW_USER" &>/dev/null; then
    print_warning "L'utilisateur $NEW_USER existe déjà"
else
    adduser --gecos "" --disabled-password $NEW_USER
    echo "$NEW_USER:$(openssl rand -base64 32)" | chpasswd
    usermod -aG sudo $NEW_USER
    print_success "Utilisateur $NEW_USER créé"
fi

# Configurer SSH pour le nouvel utilisateur
if [ ! -d "/home/$NEW_USER/.ssh" ]; then
    mkdir -p /home/$NEW_USER/.ssh
    chmod 700 /home/$NEW_USER/.ssh
    touch /home/$NEW_USER/.ssh/authorized_keys
    chmod 600 /home/$NEW_USER/.ssh/authorized_keys
    chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
    
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        echo "$SSH_PUBLIC_KEY" > /home/$NEW_USER/.ssh/authorized_keys
        print_success "Clé SSH ajoutée pour $NEW_USER"
    fi
fi

# ============================================
# 3. SÉCURISATION SSH
# ============================================

print_header "3. SÉCURISATION SSH"

# Sauvegarder la configuration SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Configurer SSH
cat > /etc/ssh/sshd_config << EOF
# Configuration SSH Sécurisée
Port $SSH_PORT
Protocol 2
ListenAddress $TAILSCALE_IP

# Authentification
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Utilisateurs autorisés
AllowUsers $NEW_USER

# Sécurité
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60

# Désactiver les fonctionnalités dangereuses
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Subsystème SFTP
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

print_success "SSH configuré sur le port $SSH_PORT (Tailscale uniquement)"

# ============================================
# 4. INSTALLATION ET CONFIGURATION FAIL2BAN
# ============================================

print_header "4. INSTALLATION FAIL2BAN"

apt install fail2ban -y

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = $USER_EMAIL
sendername = Fail2Ban-VPS
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF

systemctl enable fail2ban
systemctl restart fail2ban

print_success "Fail2Ban configuré et actif"

# ============================================
# 5. CONFIGURATION PARE-FEU UFW
# ============================================

print_header "5. CONFIGURATION PARE-FEU UFW"

apt install ufw -y

# Politiques par défaut
ufw --force default deny incoming
ufw --force default allow outgoing

# Autoriser Tailscale
ufw allow in on tailscale0

# Autoriser le port Tailscale UDP
ufw allow 41641/udp comment 'Tailscale'

# SSH uniquement via Tailscale
ufw allow in on tailscale0 to any port $SSH_PORT proto tcp comment 'SSH via Tailscale'

# Si vous avez un serveur web (décommentez si nécessaire)
# ufw allow 80/tcp comment 'HTTP'
# ufw allow 443/tcp comment 'HTTPS'

# Activer UFW
ufw --force enable

print_success "Pare-feu UFW configuré et actif"

# ============================================
# 6. DURCISSEMENT KERNEL (SYSCTL)
# ============================================

print_header "6. DURCISSEMENT KERNEL"

cat >> /etc/sysctl.conf << EOF

# === PARAMÈTRES DE SÉCURITÉ ===
# Protection IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorer les pings ICMP
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Désactiver le source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Désactiver les redirections ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Protection SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log les paquets suspects
net.ipv4.conf.all.log_martians = 1

# Désactiver IPv6 si non utilisé
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

sysctl -p

print_success "Paramètres kernel durcis"

# ============================================
# 7. INSTALLATION CLAMAV (ANTIVIRUS)
# ============================================

print_header "7. INSTALLATION CLAMAV"

apt install clamav clamav-daemon clamav-freshclam -y

systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-freshclam

# Script de scan quotidien
cat > /usr/local/bin/daily-clamscan.sh << 'EOF'
#!/bin/bash
SCAN_DIR="/"
LOG_FILE="/var/log/clamav/daily_scan_$(date +%Y%m%d_%H%M%S).log"

freshclam --quiet

clamscan -r -i \
  --exclude-dir="^/sys" \
  --exclude-dir="^/proc" \
  --exclude-dir="^/dev" \
  $SCAN_DIR > $LOG_FILE 2>&1

# Nettoyer les anciens logs (garder 30 jours)
find /var/log/clamav/ -name "daily_scan_*.log" -mtime +30 -delete
EOF

chmod +x /usr/local/bin/daily-clamscan.sh

# Ajouter au cron
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/daily-clamscan.sh") | crontab -

print_success "ClamAV installé avec scans quotidiens à 3h"

# ============================================
# 8. INSTALLATION RKHUNTER
# ============================================

print_header "8. INSTALLATION RKHUNTER"

apt install rkhunter -y

# Configuration
sed -i 's/^ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/' /etc/rkhunter.conf
sed -i 's/^ALLOW_SSH_PROT_V1=.*/ALLOW_SSH_PROT_V1=0/' /etc/rkhunter.conf

rkhunter --update
rkhunter --propupd

# Script cron quotidien
cat > /etc/cron.daily/rkhunter << EOF
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet
EOF

chmod +x /etc/cron.daily/rkhunter

print_success "rkhunter installé et configuré"

# ============================================
# 9. INSTALLATION CHKROOTKIT
# ============================================

print_header "9. INSTALLATION CHKROOTKIT"

apt install chkrootkit -y

cat > /etc/cron.daily/chkrootkit << EOF
#!/bin/bash
/usr/sbin/chkrootkit | grep -v "not found" | grep -v "not infected" > /var/log/chkrootkit.log
EOF

chmod +x /etc/cron.daily/chkrootkit

print_success "chkrootkit installé"

# ============================================
# 10. PROTECTION ANTI-MINEURS
# ============================================

print_header "10. PROTECTION ANTI-MINEURS"

cat > /usr/local/bin/detect-miners.sh << 'EOF'
#!/bin/bash
MINERS="xmrig|minerd|ccminer|cpuminer|ethminer|phoenixminer|t-rex|lolminer|nanominer|gminer|nbminer|cryptonight|monero|xmr-stak"

ps aux | grep -E "$MINERS" | grep -v grep > /tmp/miner_check.log

if [ -s /tmp/miner_check.log ]; then
    ps aux | grep -E "$MINERS" | grep -v grep | awk '{print $2}' | xargs -r kill -9
    logger -t miner-detection "Processus de minage détecté et terminé"
fi

HIGH_CPU=$(ps aux | awk '{if($3>80.0) print $0}')
if [ ! -z "$HIGH_CPU" ]; then
    echo "$HIGH_CPU" > /var/log/high_cpu.log
fi
EOF

chmod +x /usr/local/bin/detect-miners.sh

# Ajouter au cron (toutes les 15 minutes)
(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/detect-miners.sh") | crontab -

print_success "Détection de mineurs configurée"

# ============================================
# 11. INSTALLATION AUDITD
# ============================================

print_header "11. INSTALLATION AUDITD"

apt install auditd audispd-plugins -y

cat > /etc/audit/rules.d/custom.rules << EOF
# Surveiller /etc/passwd
-w /etc/passwd -p wa -k identity

# Surveiller /etc/group
-w /etc/group -p wa -k identity

# Surveiller sudo
-w /etc/sudoers -p wa -k sudo_changes

# Surveiller SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Surveiller le pare-feu
-w /etc/ufw/ -p wa -k firewall_changes

# Surveiller les binaires
-w /usr/bin/ -p wa -k binaries
-w /usr/sbin/ -p wa -k binaries

# Élévations de privilèges
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
EOF

systemctl enable auditd
systemctl restart auditd
augenrules --load

print_success "auditd configuré"

# ============================================
# 12. MISES À JOUR AUTOMATIQUES
# ============================================

print_header "12. MISES À JOUR AUTOMATIQUES"

apt install unattended-upgrades apt-listchanges -y

cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Mail "$USER_EMAIL";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades
systemctl start unattended-upgrades

print_success "Mises à jour automatiques activées"

# ============================================
# 13. SCRIPT DE VÉRIFICATION SÉCURITÉ
# ============================================

print_header "13. SCRIPT DE VÉRIFICATION"

cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/security-check_$(date +%Y%m%d).log"

echo "=== Vérification de Sécurité VPS - $(date) ===" > $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Statut UFW ---" >> $LOG_FILE
ufw status verbose >> $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Connexions Réseau Actives ---" >> $LOG_FILE
ss -tulpn >> $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Utilisateurs Connectés ---" >> $LOG_FILE
who >> $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Dernières Tentatives Échouées ---" >> $LOG_FILE
grep "Failed password" /var/log/auth.log | tail -20 >> $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Top Processus CPU ---" >> $LOG_FILE
ps aux --sort=-%cpu | head -11 >> $LOG_FILE
echo "" >> $LOG_FILE

echo "--- Espace Disque ---" >> $LOG_FILE
df -h >> $LOG_FILE
EOF

chmod +x /usr/local/bin/security-check.sh

# Ajouter au cron quotidien
(crontab -l 2>/dev/null; echo "0 5 * * * /usr/local/bin/security-check.sh") | crontab -

print_success "Script de vérification configuré"

# ============================================
# 14. DURCISSEMENT DES PERMISSIONS
# ============================================

print_header "14. DURCISSEMENT DES PERMISSIONS"

chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chmod 600 /etc/crontab

print_success "Permissions durcies"

# ============================================
# 15. DÉSACTIVER LES CORE DUMPS
# ============================================

print_header "15. DÉSACTIVATION CORE DUMPS"

echo "* hard core 0" >> /etc/security/limits.conf
echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf
sysctl -p

print_success "Core dumps désactivés"

# ============================================
# 16. CONFIGURATION FINALE
# ============================================

print_header "16. CONFIGURATION FINALE"

# Créer le fichier de documentation
cat > /root/securite-config.txt << EOF
=== CONFIGURATION DE SÉCURITÉ VPS ===
Date de configuration: $(date)

UTILISATEUR: $NEW_USER
PORT SSH: $SSH_PORT
IP TAILSCALE: $TAILSCALE_IP
IP PUBLIQUE: $PUBLIC_IP
EMAIL ALERTES: $USER_EMAIL

ACCÈS SSH:
  ssh -p $SSH_PORT $NEW_USER@$TAILSCALE_IP

SERVICES ACTIFS:
  ✓ UFW (pare-feu)
  ✓ Fail2Ban
  ✓ ClamAV (scans quotidiens à 3h)
  ✓ rkhunter
  ✓ chkrootkit
  ✓ auditd
  ✓ Détection mineurs (toutes les 15min)
  ✓ Mises à jour automatiques
  ✓ Rapport sécurité (quotidien à 5h)

IMPORTANT:
  - SSH accessible UNIQUEMENT via Tailscale
  - Authentification par clé uniquement
  - Root login désactivé
  
COMMANDES UTILES:
  sudo ufw status verbose
  sudo fail2ban-client status sshd
  sudo tailscale status
  /usr/local/bin/security-check.sh
  
LOGS:
  /var/log/auth.log (SSH)
  /var/log/ufw.log (Pare-feu)
  /var/log/fail2ban.log (Fail2Ban)
  /var/log/clamav/ (Antivirus)
EOF

print_success "Documentation créée dans /root/securite-config.txt"

# ============================================
# RÉSUMÉ FINAL
# ============================================

print_header "INSTALLATION TERMINÉE"

echo -e "${GREEN}"
cat << EOF
╔══════════════════════════════════════════════════════════════╗
║                  SÉCURISATION TERMINÉE !                     ║
╚══════════════════════════════════════════════════════════════╝

Votre VPS est maintenant sécurisé avec:

  ✓ Pare-feu UFW actif
  ✓ SSH sécurisé (port $SSH_PORT, Tailscale uniquement)
  ✓ Fail2Ban actif
  ✓ ClamAV + rkhunter + chkrootkit
  ✓ Protection anti-mineurs
  ✓ Surveillance auditd
  ✓ Mises à jour automatiques

PROCHAINES ÉTAPES CRITIQUES:

1. TESTEZ la connexion SSH dans une NOUVELLE fenêtre:
   ssh -p $SSH_PORT $NEW_USER@$TAILSCALE_IP

2. NE FERMEZ PAS cette session avant d'avoir testé!

3. Consultez la documentation:
   cat /root/securite-config.txt

4. Vérifiez le statut:
   sudo ufw status verbose
   sudo fail2ban-client status
   tailscale status

AVERTISSEMENT:
  - SSH est maintenant accessible UNIQUEMENT via Tailscale
  - Si vous perdez l'accès Tailscale, utilisez la console VPS

EOF
echo -e "${NC}"

print_warning "IMPORTANT: Testez SSH avant de fermer cette session!"
print_warning "Redémarrage du SSH dans 5 secondes..."
sleep 5

systemctl restart sshd

print_success "SSH redémarré"
print_success "Installation complète!"

exit 0
