#!/bin/bash
echo '*******************************************************************'
echo 'Script maker   : Nathan'
echo 'Homepage       : http://blog.netimed.cn'
echo 'E-Mail Address ： nathan@netimed.cn'
echo 'Maked Date     : Nov. 6 2019'
echo 'Tips:This domain name will be used globally, and will use ‘mail’ as'
echo 'the tertiary domain for web access. Please set the corresponding   '
echo 'domain name resolution.                                            '
echo '*******************************************************************'
echo '                                                                   '
read -p "*Please Input Your Domain Name:  " domainame
echo '140.82.114.4 github.com
199.232.5.194 github.global.ssl.fastly.net
140.82.113.10 codeload.github.com
52.217.32.124 github-production-release-asset-2e65be.s3.amazonaws.com' >> /etc/hosts
sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
setenforce 0
yum makecache
yum  install vim bash-c* net-tool* wget unzip -y
hostnamectl set-hostname mail.$domainame
cd  /etc/yum.repos.d/
mkdir ./bak
mv CentOS-* ./bak/
yum clean all
#wget http://mirrors.163.com/.help/CentOS7-Base-163.repo
wget http://mirrors.aliyun.com/repo/Centos-7.repo
yum makecache
yum repolist
yum list installed | grep php
yum remove php* -y
yum  install epel-release -y
yum  install libmcrypt-devel libmcrypt -y
rpm -Uvh http://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/l/libc-client-2007f-16.el7.x86_64.rpm
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
yum  update -y
yum  install httpd unzip libmemcached libmemcached-devel zlib zlib-devel libmcrypt libmcrypt-devel mcrypt mhash  postfix   mysql  mysql-devel  mariadb-server  pcre pcre-devel telnet cyrus-sasl cyrus-sasl-plain dovecot dovecot-mysql dovecot-devel  -y 
yum  install php56w-common php56w-mysql php56w php56w-pecl-Fileinfo php56w-mcrypt php56w-devel php56w-common php56w-mbstring php56w-gd php56w-imap  php56w-pear php56w-xml php56w-xmlrpc php56w-opcache php56w-cli php56w-ldap php56w-mysql php56w-odbc php56w-pdo php56w-pgsql php56w-soap php56w-pecl-apc php56w-pecl-memcache -y
useradd vmail -u 2000 -d   /var/vmail -m -s /sbin/nologin
echo '
AddType   application/x-httpd-php .php
PHPIniDir   "/etc/php.ini"
' >> /etc/httpd/conf/httpd.conf
sed -i 's/DirectoryIndex index.html/DirectoryIndex index.html index.php index.html.var/g'  /etc/httpd/conf/httpd.conf
sed -i 's/User apache/User vmail/g'  /etc/httpd/conf/httpd.conf
sed -i 's/Group apache/Group vmail/g'  /etc/httpd/conf/httpd.conf
sed -i 's/#ServerName www.example.com:80/ServerName localhost:80/g'  /etc/httpd/conf/httpd.conf
sed -i 's/Listen\ 80/Listen\ 0.0.0.0:808/g'  /etc/httpd/conf/httpd.conf
#
echo -e "<?php\nphpinfo();\n?>" >  /var/www/html/index.php
#
systemctl enable httpd
systemctl start httpd 
systemctl status httpd
#Install MariaDB, HTTPD, MariaDB-Server, Mod_SSL
systemctl start mariadb
systemctl enable mariadb
#Open FireWall Ports
systemctl enable firewalld.service
systemctl start  firewalld.service
firewall-cmd --zone=public --add-port=110/tcp --permanent
firewall-cmd --zone=public --add-port=443/tcp --permanent
firewall-cmd --zone=public --add-port=143/tcp --permanent
firewall-cmd --zone=public --add-port=993/tcp --permanent
firewall-cmd --zone=public --add-port=995/tcp --permanent
firewall-cmd --zone=public --add-port=465/tcp --permanent
firewall-cmd --zone=public --add-port=587/tcp --permanent
firewall-cmd --zone=public --add-port=25/tcp --permanent
firewall-cmd --zone=public --add-port=808/tcp --permanent
firewall-cmd --reload
firewall-cmd --list-all
#Secure mariaDB + Create root password
#Run security initialization script
#Do you want to set the database administrator root password? This script defaults to setting the root password.
# Whether to prohibit root remote login, this script defaults to prohibit root remote login.
# Whether to delete the anonymous user account, this script defaults to delete the anonymous user account.
# Whether to delete the test database, this script defaults to delete the test database.
echo -e "\ny\nadmin\nadmin\ny\ny\ny\ny" | mysql_secure_installation
echo '#
[client]
port=3306
socket=/var/lib/mysql/mysql.sock
password=admin
#' >> /etc/my.cnf
mysql -uroot -padmin -e "set password = password('admin');"
mysql -uroot -padmin -e "create database postfix;"
mysql -uroot -padmin -e "grant all   on postfix.* to postfix@'localhost' identified by 'postfix';"
mysql -uroot -padmin -e "FLUSH PRIVILEGES;"
mysql -uroot -padmin -e "show databases;"
#
#Install PostfixAdmin
wget https://excellmedia.dl.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-2.3.6/postfixadmin-2.3.6.tar.gz
tar xzf postfixadmin-2.3.6.tar.gz
sudo mv postfixadmin-2.3.6/ /var/www/postfixadmin
rm -f postfixadmin-2.3.6.tar.gz
mkdir /var/www/postfixadmin/templates_c
chown -R vmail. /var/www/postfixadmin
mv  /var/www/postfixadmin* /var/www/html/
cd /var/www/html/postfixadmin/
rm -rf phpMyAdmin-4.9.0.1-all-languages*
cp config.inc.php config.inc.php.bak
cp setup.php   setup.php.bak
sed -i "s/\$CONF\['configured'] = false\;/\$CONF\['configured'] = true\;/g"  config.inc.php
sed -i "s/\$CONF\['database_type'] = 'mysql'\;/\$CONF\['database_type'] = 'mysql'\;/g" config.inc.php
sed -i "s/\$CONF\['database_password'] = 'postfixadmin'\;/\$CONF\['database_password'] = 'postfix'\;/g" config.inc.php
sed -i "s/\$CONF\['admin_email'] = 'postmaster@change-this-to-your.domain.tld'\;/\$CONF\['admin_email'] = 'admin@$domainame'\;/g" config.inc.php
sed -i "s/\$CONF\['encrypt'] = 'md5crypt'\;/\$CONF\['encrypt'] =   'dovecot:CRAM-MD5'\\;/g" config.inc.php
sed -i "s#\/usr\/sbin\/dovecotpw#\/usr\/bin\/doveadm\ pw#g" config.inc.php
sed -i "s/\$CONF\['domain_path'] = 'NO'\;/\$CONF\['domain_path'] = 'YES'\;/g" config.inc.php
sed -i "s/\$CONF\['domain_in_mailbox'] = 'YES'\;/\$CONF\['domain_in_mailbox'] = 'NO'\;/g" config.inc.php
sed -i "s/\$CONF\['aliases'] = '10'\;/\$CONF\['aliases'] = '1000'\;/g" config.inc.php
sed -i "s/\$CONF\['mailboxes'] = '10'\;/\$CONF\['mailboxes'] = '1000'\;/g" config.inc.php
sed -i "s/\$CONF\['maxquota'] = '10'\;/\$CON\F['maxquota'] = '1000'\;/g" config.inc.php
sed -i "s/\$CONF\['fetchmail'] = 'YES'\;/\$CONF\['fetchmail'] = 'NO'\;/g" config.inc.php
sed -i "s/\$CONF\['quota'] = 'NO'\;/\$CONF\['quota'] = 'YES'\;/g" config.inc.php
sed -i "s/\$CONF\['used_quotas'] = 'NO'\;/\$CONF\['used_quotas'] = 'YES'\;/g" config.inc.php
sed -i "s/\$CONF\['new_quota_table'] = 'NO'\;/\$CONF\['new_quota_table'] = 'YES'\;/g" config.inc.php
sed -i "s/abuse@change-this-to-your.domain.tld/abuse@$domainame/g" config.inc.php
sed -i "s/hostmaster@change-this-to-your.domain.tld/hostmaster@$domainame/g" config.inc.php
sed -i "s/postmaster@change-this-to-your.domain.tld/postmaster@$domainame/g" config.inc.php
sed -i "s/webmaster@change-this-to-your.domain.tld/webmaster@$domainame/g" config.inc.php
sed -i "s/autoreply.change-this-to-your.domain.tld/autoreply.$domainame/g" config.inc.php
sed -i "s/http:\/\/change-this-to-your.domain.tld\/main/http:\/\/mail.$domainame:808\/main/g" config.inc.php
sed -i "s/Return\ to\ change-this-to-your.domain.tld/Return\ to\ mail.$domainame:808/g" config.inc.php
sed -i "s/http:\/\/change-this-to-your.domain.tld/http:\/\/mail.$domainame:808/g" config.inc.php
sed -i "2idate_default_timezone_set('PRC')\;" /var/www/html/postfixadmin/backup.php
systemctl start mariadb
systemctl enable mariadb
systemctl status mariadb
mysql -uroot -padmin -e "flush privileges;"
mysql -upostfix -ppostfix -e "show databases;"
mysql -upostfix -ppostfix -e "show tables from postfix;"
#
chown -R   vmail.vmail  /var/www/html/postfixadmin/
chown -R   vmail.vmail /var/lib/php/session/
#
touch /usr/local/bin/maildir-creation.sh
chmod +x /usr/local/bin/maildir-creation.sh
echo '#!/bin/bash
#
HOME_DIR="/var/vmail"
#
USER_NAME="vmail"
#
GROUP_NAME="vmail"
#
if[ ! -d   ${HOME_DIR}/$1 ] ;then
#
   mkdir${HOME_DIR}/$1
#
   chown-R   ${USER_NAME}.${GROUP_NAME} ${HOME_DIR}/$1
#
fi
#
mkdir${HOME_DIR}/$1/$2
#
chown-R   ${USER_NAME}.${GROUP_NAME} ${HOME_DIR}/$1/$2
#
#' > /usr/local/bin/maildir-creation.sh
#
touch /usr/local/bin/maildir-deletion.sh
chmod +x /usr/local/bin/maildir-deletion.sh
echo '#!/bin/bash
#
# vmta ALL =   NOPASSWD: /usr/local/bin/maildir-deletion.sh
#
#
#
if[ $# -ne 2 ] ; then
#
 exit127
#
fi
#
DOMAIN="$1"
#
USER="$2"
#
HOME_DIR="/var/vmail"
#
USER_DIR="${HOME_DIR}/${DOMAIN}/${USER}"
#
TRASH_DIR="${HOME_DIR}/deleted-maildirs"
#
DATE=`date  "+%Y%m%d_%H%M%S"`
#
if[ ! -d   "${TRASH_DIR}/${DOMAIN}" ] ;then
#
   mkdir-p   "${TRASH_DIR}/${DOMAIN}"
#
fi
#
if[ -d   "${USER_DIR}" ] ;then
#
   mv${USER_DIR}   ${TRASH_DIR}/${DOMAIN}/${USER}-${DATE}
#
fi ' > /usr/local/bin/maildir-deletion.sh
#
mkdir   /var/vmail/deleted-maildirs
chown -R   vmail.vmail /var/vmail/deleted-maildirs/
chmod 750   /usr/local/bin/maildir-*
chown vmail.vmail   /usr/local/bin/maildir-*
#
sudo echo '
vmail ALL =   NOPASSWD: /usr/local/bin/maildir-creation.sh
#
vmail ALL =   NOPASSWD: /usr/local/bin/maildir-deletion.sh
' >>  /etc/sudoers
#
cd   /var/www/html/postfixadmin/
sed -i  "s/\$CONF\['setup_password']\ =\ 'changeme'\;/\$CONF\['setup_password']\ =\ '243914c37a78bd32c79ebfd95ba4a47c:07b4fb7995a6f9388ed3240abc54998b2b8e93f6'\;/g"  config.inc.php
sed -i  '229i\ \ \ \ \ \ \ \ \ \ \ \ system("sudo\ \/usr\/local\/bin\/maildir-creation.sh\ $fDomain\ ".$_POST['fUsername'])\;' create-mailbox.php
sed -i  '147i\ \ \ \ \ \ \ \ \ \ \ \ $userarray=explode("@",$fDelete)\;\n\ \ \ \ \ \ \ \ \ \ \ \ $user=$userarray[0]\;\n\ \ \ \ \ \ \ \ \ \ \ \ $domain=$userarray[1]\;\n\ \ \ \ \ \ \ \ \ \ \ \ system("sudo   /usr/local/bin/maildir-deletion.sh $domain $user")\;'  delete.php
#
#Install And Config PHPMYADMIN
#wget https://files.phpmyadmin.net/phpMyAdmin/4.9.0.1/phpMyAdmin-4.9.0.1-all-languages.zip
wget https://files.phpmyadmin.net/phpMyAdmin/4.9.1/phpMyAdmin-4.9.1-all-languages.zip
unzip phpMyAdmin-*-all-languages.zip
mkdir /var/www/html/phpmyadmin
mv  phpMyAdmin-*-all-languages/* /var/www/html/phpmyadmin
cd /var/www/html/phpmyadmin
mkdir tmp
chmod 777 tmp
cp config.sample.inc.php config.inc.php
sed -i "s/\$cfg\['blowfish_secret']\ =\ ''\;/\$cfg\['blowfish_secret']\ =\ 'abcdefghijklmnopqrstuvwxyzabcdefgh'\;/g" config.inc.php
mysql -uroot -padmin -e "grant all on postfix.* to postfix@'localhost' identified by 'postfix';"
mysql -uroot -padmin -e "flush privileges;"
systemctl restart mariadb
#Configure postfix mailing agent
#
sed -i "s/#myhostname\ =\ host.domain.tld/myhostname\ =\ mail.$domainame/g"  /etc/postfix/main.cf
sed -i "s/#mydomain\ =\ domain.tld/mydomain\ =\ $domainame/g"  /etc/postfix/main.cf
sed -i 's/#mynetworks\ =\ 168.100.189.0\/28,\ 127.0.0.0\/8/mynetworks\ =\ 172.16.0.0\/16,\ 127.0.0.0\/8/g'  /etc/postfix/main.cf
sed -i 's/#relay_domains = $mydestination/relay_domains = $mydestination/g'  /etc/postfix/main.cf
sed -i 's/#myorigin\ =\ \$mydomain/myorigin\ =\ \$mydomain/g'  /etc/postfix/main.cf
sed -i 's/inet_interfaces\ =\ localhost/inet_interfaces\ =\ all/g'  /etc/postfix/main.cf
sed -i 's/#mynetworks_style\ =\ host/mynetworks_style\ =\ host/g'  /etc/postfix/main.cf
echo 'message_size_limit = 512000000'  >> /etc/postfix/main.cf
echo 'mailbox_size_limit = 51200000000'  >> /etc/postfix/main.cf
#
echo '
virtual_mailbox_domains = proxy:mysql:/etc/postfix/mysql_virtual_domains_maps.cf
#
virtual_alias_maps =   proxy:mysql:/etc/postfix/mysql_virtual_alias_maps.cf
#
virtual_mailbox_maps   = proxy:mysql:/etc/postfix/mysql_virtual_mailbox_maps.cf
#
# Additionalforquota support
#
virtual_create_maildirsize   = yes
#
virtual_mailbox_extended   = yes
#
virtual_mailbox_limit_maps   = mysql:/etc/postfix/mysql_virtual_mailbox_limit_maps.cf
#
virtual_mailbox_limit_override   = yes
#
virtual_maildir_limit_message   = Sorry,thisuser has exceeded their disk space quota,   pleasetryagain later.
#
virtual_overquota_bounce   = yes
#
#Specify the   user/group that owns the mail folders. I'm not sure if this is strictly   necessary when using Dovecot's LDA.
#
virtual_uid_maps =static:2000
#
virtual_gid_maps =static:2000
#
proxy_read_maps =   $local_recipient_maps $mydestination $virtual_alias_maps   $virtual_alias_domains $virtual_mailbox_maps $virtual_mailbox_domains   $relay_recipient_maps $relay_domains $canonical_maps $sender_canonical_maps   $recipient_canonical_maps $relocated_maps $transport_maps $mynetworks   $virtual_mailbox_limit_maps
' >> /etc/postfix/main.cf
postconf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT   domain FROM domain WHERE domain='%s' AND active = '1'
#
#optional query to   use when relaying for backup MX
#
#query = SELECT   domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'
" > /etc/postfix/mysql_virtual_domains_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT goto   FROM alias WHERE address='%s'   AND active = '1'
" >  /etc/postfix/mysql_virtual_alias_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT   CONCAT(domain,'/',maildir) FROM mailbox WHERE username='%s' AND active = '1'
" > /etc/postfix/mysql_virtual_mailbox_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECTquotaFROM mailbox WHERE   username='%s' AND active = '1'
" > /etc/postfix/mysql_virtual_mailbox_limit_maps.cf
#
postconf -a
#
echo '
smtpd_sasl_auth_enable   = yes
#
smtpd_sasl_type =   dovecot
#
smtpd_sasl_path = /var/spool/postfix/private/auth
#
smtpd_sasl_security_options   = noanonymous
#
broken_sasl_auth_clients   = yes
#
smtpd_recipient_restrictions   =  permit_sasl_authenticated,   permit_mynetworks, reject_unauth_destination
#
virtual_transport =   dovecot
#
dovecot_destination_recipient_limit   = 1
#
' >> /etc/postfix/main.cf
#
echo '
dovecot   unix    -       n       n         -       -       pipe
#
  flags=DRhu user=vmail:vmail   argv=/usr/libexec/dovecot/dovecot-lda -f ${sender} -d ${recipient}
' >> /etc/postfix/master.cf
postconf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT domain  FROM  domain  WHERE domain='%s' AND active = '1'
#
#optional query to   use when relaying for backup MX
#
#query = SELECT   domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'
" > /etc/postfix/mysql_virtual_domains_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT goto   FROM  alias  WHERE address='%s'   AND active = '1'
" >  /etc/postfix/mysql_virtual_alias_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT   CONCAT(domain,'/',maildir) FROM mailbox WHERE username='%s' AND active = '1'
" > /etc/postfix/mysql_virtual_mailbox_maps.cf
#
echo "
user = postfix
#
password = postfix
#
hosts = localhost
#
dbname = postfix
#
query = SELECT  quota  FROM mailbox WHERE   username='%s' AND active = '1'
" > /etc/postfix/mysql_virtual_mailbox_limit_maps.cf
#
postconf -a
echo '
smtpd_sasl_auth_enable   = yes
#
smtpd_sasl_type =   dovecot
#
smtpd_sasl_path = /var/run/dovecot/auth-client
#
smtpd_sasl_security_options   = noanonymous
#
broken_sasl_auth_clients   = yes
#
smtpd_recipient_restrictions   =  permit_sasl_authenticated,   permit_mynetworks, reject_unauth_destination
#
virtual_transport =   dovecot
#
dovecot_destination_recipient_limit   = 1
#
' >> /etc/postfix/main.cf
#
echo '
dovecot   unix    -       n       n         -       -       pipe
#
  flags=DRhu user=vmail:vmail   argv=/usr/libexec/dovecot/dovecot-lda -f ${sender} -d ${recipient}
' >> /etc/postfix/master.cf
#
#Install and configure the dovecot mail retrieval agent
#
sed -i 's/#protocols\ =\ imap\ pop3\ lmtp/protocols\ =\ imap\ pop3/g'  /etc/dovecot/dovecot.conf
echo 'listen = *' >> /etc/dovecot/dovecot.conf
sed -i 's/dict\ {/dict\ {\n\ \ quota=\ mysql:\/etc\/dovecot\/dovecot-dict-sql.conf.ext/g'  /etc/dovecot/dovecot.conf
sed -i 's/#disable_plaintext_auth\ =\ yes/disable_plaintext_auth\ =\ no/g'  /etc/dovecot/conf.d/10-auth.conf
sed -i 's/auth_mechanisms\ =\ plain/auth_mechanisms\ =\ plain\ login\ cram-md5/g' /etc/dovecot/conf.d/10-auth.conf
sed -i 's/#!include\ auth-sql.conf.ext/!include\ auth-sql.conf.ext/g'  /etc/dovecot/conf.d/10-auth.conf
sed -i 's/#mail_location\ =/mail_location\ =\ maildir:%hMaildir/g' /etc/dovecot/conf.d/10-mail.conf
sed -i 's/\ #unix_listener\ \/var\/spool\/postfix\/private\/auth\ {/\ unix_listener\ \/var\/spool\/postfix\/private\/auth\ {\n\ \ \ \ mode\ =\ 0600\n\ \ }/g' /etc/dovecot/conf.d/10-master.conf
sed -i 's/\ \ \ \ #mode\ =\ 0666/\ \ \ \ mode\ =\ 0600/g'  /etc/dovecot/conf.d/10-master.conf
sed -i 's/\ \ \ \ #mode\ =\ 0600/\ \ \ \ mode\ =\ 0600/g'  /etc/dovecot/conf.d/10-master.conf
sed -i 's/\ \ \ \ #user\ =/\ \ \ \ user\ =\ vmail/g'  /etc/dovecot/conf.d/10-master.conf
sed -i 's/\ \ \ \ #group\ =/\ \ \ \ group\ =\ vmail/g'  /etc/dovecot/conf.d/10-master.conf
sed -i "s/protocol\ lda\ {/protocol lda\ {\n\ \ mail_plugins\ =quota\n\ \ postmaster_address\ =\ admin@$domainame/g"  /etc/dovecot/conf.d/15-lda.conf
sed -i 's/\ \ #mail_plugins\ =\ $mail_plugins/\ \ mail_plugins\ =quota\ imap_quota/g'  /etc/dovecot/conf.d/20-imap.conf
sed -i 's/\ \ #mail_plugins\ =\ \$mail_plugins/\ \ pop3_uidl_format\ =\ %08Xu%08Xv\n\ \ mail_plugins\ =quota/g'  /etc/dovecot/conf.d/20-pop3.conf
sed -i 's/#quota_rule\ =\ \*:storage=1G/quota_rule\ =\ \*:storage=1G/g' /etc/dovecot/conf.d/90-quota.conf
sed -i 's/#quota\ =\ dict:User\ quota::proxy::quota/quota\ =\ dict:User\ quota::proxy::quota/g'  /etc/dovecot/conf.d/90-quota.conf
#sed -i 's/ssl\ =\ required/ssl\ =\ no/g'  /etc/dovecot/conf.d/10-ssl.conf
#
echo "driver = mysql
connect = host=localhost dbname=postfix user=postfix password=postfix
default_pass_scheme = CRAM-MD5
user_query = SELECT CONCAT('/var/vmail/', maildir) AS home, 2000 AS uid, 2000 AS gid, CONCAT('*:bytes=', quota) as quota_rule FROM mailbox WHERE username = '%u' AND active=1
password_query = SELECT username AS user, password, CONCAT('/var/vmail/', maildir) AS userdb_home, 2000 AS userdb_uid, 2000 AS userdb_gid, CONCAT('*:bytes=', quota) as userdb_quota_rule FROM mailbox WHERE username = '%u' AND active=1
#" > /etc/dovecot/dovecot-sql.conf.ext
#
echo '
connect = host=localhost dbname=postfix user=postfix password=postfix 
map { 
  pattern = priv/quota/storage
  table = quota2 
  username_field = username 
  value_field = bytes 
} 
map { 
  pattern = priv/quota/messages
  table = quota2 
  username_field = username 
  value_field = messages 
}
#' > /etc/dovecot/dovecot-dict-sql.conf.ext
#

systemctl restart postfix.service
systemctl restart dovecot.service
systemctl status postfix.service
systemctl status dovecot.service
chmod 777 /var/run/dovecot/auth-client
systemctl enable saslauthd
systemctl restart saslauthd
netstat -luntp |  grep -E ':80|:25|:110|:993|:995|:465|:587'
ls -l /var/run/dovecot/auth-client
###Virus scanning and spam filtering are installed in this version
#
yum install   amavisd-new clamav clamav-devel clamd   spamassassin  clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y
systemctl enable clamd@scan.service  amavisd.service spamassassin.service
#
sed -i 's/#\ \@bypass_virus_checks_maps/\@bypass_virus_checks_maps/g'   /etc/amavisd/amavisd.conf
sed -i 's/#\ \@bypass_spam_checks_maps/\@bypass_spam_checks_maps/g'   /etc/amavisd/amavisd.conf
sed -i 's/#\ \$bypass_decode_parts/\$bypass_decode_parts/g'  /etc/amavisd/amavisd.conf
sed -i "s/\$mydomain\ =\ 'example.com';/\$mydomain\ =\ '$domainame';/g"  /etc/amavisd/amavisd.conf
#sed -i "s/\$MYHOME\ =\ '\/var\/spool\/amavisd';/\$MYHOME\ =\ '\/var\/amavisd';/g"  /etc/amavisd/amavisd.conf
sed -i "s/#\ \$myhostname\ =\ 'host.example.com';/\$myhostname\ =\ 'mail.$domainame';/g" /etc/amavisd/amavisd.conf
sed -i "s/\$virus_admin\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ =\ undef;/\$virus_admin\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ =\ 'postmaster\\\@\$mydomain';/g" /etc/amavisd/amavisd.conf
sed -i "s/\$mailfrom_notify_admin\ \ \ \ \ =\ undef;/\$mailfrom_notify_admin\ \ \ \ \ =\ 'postmaster\\\@\$mydomain';/g" /etc/amavisd/amavisd.conf
sed -i "s/\$mailfrom_notify_recip\ \ \ \ \ =\ undef;/\$mailfrom_notify_recip\ \ \ \ \ =\ 'postmaster\\\@\$mydomain';/g" /etc/amavisd/amavisd.conf
sed -i "s/\$mailfrom_notify_spamadmin\ =\ undef;/\$mailfrom_notify_spamadmin\ =\ 'postmaster\\\@\$mydomain';/g" /etc/amavisd/amavisd.conf 
#
sed -i '11iamavisfeed unix\ \ \ \ -\ \ \ \ \ \ \ \ \ -\ \ \ \ \ \ \ n\ \ \ \ \ \ \ -\ \ \ \ \ \ \ \ \ 2\ \ \ \ \ smtp'  /etc/postfix/master.cf
sed -i '12i\ \ -o\ smtp_data_done_timeout=1200'  /etc/postfix/master.cf
sed -i '13i\ \ -o\ smtp_send_xforward_command=yes' /etc/postfix/master.cf
sed -i '14i\ \ -o\ smtp_tls_note_starttls_offer=no' /etc/postfix/master.cf
sed -i '15i\ \ -o\ disable_dns_lookups=yes' /etc/postfix/master.cf
sed -i '16i\ \ -o\ max_use=20' /etc/postfix/master.cf
#
sed -i '17i127.0.0.1:10025\ inet\ n\ \ \ \ -\ \ \ \ \ \ \ \ \ n\ \ \ \ \ \ \ -\ \ \ \ \ \ \ -\ \ \ \ \ \ \ smtpd'  /etc/postfix/master.cf
sed -i '18i\ \ -o\ content_filter='  /etc/postfix/master.cf
sed -i '19i\ \ -o\ smtpd_delay_reject=no' /etc/postfix/master.cf
sed -i '20i\ \ -o\ smtpd_client_restrictions=permit_mynetworks,reject' /etc/postfix/master.cf
sed -i '21i\ \ -o\ smtpd_helo_restrictions=' /etc/postfix/master.cf
sed -i '22i\ \ -o\ smtpd_sender_restrictions=' /etc/postfix/master.cf
sed -i '23i\ \ -o\ smtpd_recipient_restrictions=permit_mynetworks,reject'  /etc/postfix/master.cf
sed -i '24i\ \ -o\ smtpd_data_restrictions=reject_unauth_pipelining' /etc/postfix/master.cf
sed -i '25i\ \ -o\ smtpd_end_of_data_restrictions=' /etc/postfix/master.cf
sed -i '26i\ \ -o\ smtpd_restriction_classes=' /etc/postfix/master.cf
sed -i '27i\ \ -o\ mynetworks=127.0.0.0/8' /etc/postfix/master.cf
sed -i '28i\ \ -o\ smtpd_error_sleep_time=0'  /etc/postfix/master.cf
sed -i '29i\ \ -o\ smtpd_soft_error_limit=1001' /etc/postfix/master.cf
sed -i '30i\ \ -o\ smtpd_hard_error_limit=1000' /etc/postfix/master.cf
sed -i '31i\ \ -o\ smtpd_client_connection_count_limit=0' /etc/postfix/master.cf
sed -i '32i\ \ -o\ smtpd_client_connection_rate_limit=0' /etc/postfix/master.cf
sed -i '33i\ \ -o\ receive_override_options=no_header_body_checks,no_unknown_recipient_checks,no_milters,no_address_mappings'  /etc/postfix/master.cf
sed -i '34i\ \ -o\ local_header_rewrite_clients=' /etc/postfix/master.cf
sed -i '35i\ \ -o\ smtpd_milters=' /etc/postfix/master.cf
sed -i '36i\ \ -o\ local_recipient_maps=' /etc/postfix/master.cf
#
echo '#filter mail' >> /etc/postfix/main.cf
echo 'content_filter = amavisfeed:[127.0.0.1]:10024' >> /etc/postfix/main.cf
sed -i 's/Example/#Example/g' /etc/clamd.d/scan.conf
sed -i '94iLocalSocket /var/run/clamd.scan/clamd.sock'  /etc/clamd.d/scan.conf
sed -i 's/#\ FRESHCLAM_DELAY=//g' /etc/sysconfig/freshclam
ln -s '/usr/lib/systemd/system/clamd@scan.service''/etc/systemd/system/multi-user.target.wants/clamd@scan.service'
echo '# Run the freshclam as daemon 

[Unit] 

Description = freshclam scanner 

After = network.target 

[Service] 

Type = forking 

ExecStart = /usr/bin/freshclam -d -c 4 

Restart = on-failure 

PrivateTmp = true 

[Install] 

WantedBy=multi-user.target' >  /usr/lib/systemd/system/clam-freshclam.service
systemctl enable clam-freshclam.service
systemctl start clam-freshclam.service
systemctl status clam-freshclam.service
systemctl enable spamassassin
systemctl restart spamassassin
systemctl enable  amavisd
systemctl restart  amavisd
killall freshclam 
freshclam
#
systemctl restart postfix.service  
systemctl restart  clamd@amavisd.service  
systemctl restart  clamd@scan.service 
systemctl status -l postfix.service  clamd@amavisd.service clamd@scan.service amavisd spamassassin
cd 
wget http://www.eicar.org/download/eicar_com.zip
clamscan --infected --remove --recursive .
#
yum install -y dovecot-pigeonhole
sed -i 's/protocols\ =\ imap\ pop3/protocols\ =\ imap\ pop3\ sieve/g'  /etc/dovecot/dovecot.conf
sed -i 's/\ \ mail_plugins\ =quota/\ \ mail_plugins\ =quota\ sieve/g'  /etc/dovecot/conf.d/15-lda.conf
systemctl restart dovecot
systemctl enable dovecot
systemctl status dovecot
chmod 777  /var/run/dovecot/auth-client
netstat -ntulp | grep 4190
mkdir /MailBackup
#
echo '#!/bin/bash
chmod 777 /var/run/dovecot/auth-client
echo "*************************************************************************************" >> /var/log/auth-client.log
date >> /var/log/auth-client.log
ls -l /var/run/dovecot/auth-client >> /var/log/auth-client.log' > /etc/postfix/auth-client_log.sh
#
echo "#!/bin/bash
cd /MailBackup
echo 'Start backing up the mail...OK'
backupfilename=\`date +%F | sed 's/-//g'\`\`date +%T | sed 's/://g'\`
tar -cvpzf backup_\$backupfilename.tar.gz  /var/vmail/$domainame/*
echo 'Backup mail data is completed...OK'
find /MailBackup -ctime +5 -name \'*.tar.gz\' -exec rm -rf {} \;
#
#FOR TEST: Test delete files older than 3 minutes：
#find /MailBackup -cmin +3  -name '*.tar.gz' -exec rm -rf {} \;
#
echo 'Deleted the backup files successfully'" > /etc/postfix/backup_webmail.sh
#
echo '*/5 * * * * sh /etc/postfix/auth-client_log.sh' >> /var/spool/cron/root
echo '0 3 */1 * * sh /etc/postfix/backup_webmail.sh' >> /var/spool/cron/root
#
#install and configure WebMail (Roundcubemai
cd /var/www/html/
wget https://codeload.github.com/roundcube/roundcubemail/zip/master
mv master master.zip
unzip master.zip
rm  -rf master.zip
rm -rf  index*
mv roundcubemail-master/* .   
chown  -R  vmail. *
mysql -uroot -padmin -e "CREATE DATABASE webmail DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;"
mysql -uroot -padmin -e "grant all on webmail.* to webmail@'localhost' identified by 'webmail';"
mysql -uwebmail -pwebmail -D webmail -e "source /var/www/html/SQL/mysql.initial.sql;"
mysql -uroot -padmin -e "FLUSH PRIVILEGES;"
mysql -uwebmail -pwebmail -D webmail -e "show tables;"
cp ./config/config.inc.php.sample ./config/config.inc.php
sed -i "s/roundcube:pass@localhost\/roundcubemail/webmail:webmail@localhost\/webmail/g" ./config/config.inc.php
sed -i 's/\;date.timezone\ =/date.timezone\ =\ Asia\/Shanghai/g' /etc/php.ini
systemctl restart httpd.service
sed -i 's/;\ \ \ \ \ session.save_path\ =\ "N\;\/path"/\ \ \ \ \ session.save_path\ =\ "\/var\/lib\/php\/session"/g' /etc/php.ini
chown -R .vmail /var/lib/php/session/
systemctl restart httpd
#
cd   /var/www/html/plugins/managesieve/
cp config.inc.php.dist   config.inc.php 
sed -i "s/\$config\['managesieve_port']\ =\ null;/\$config\['managesieve_port']\ =\ 4190;/g"  config.inc.php 
sed -i "83i\ \ \ \ 'managesieve'," /var/www/html/config/config.inc.php
sed -i "84i\ \ \ \ 'attachment_reminde'," /var/www/html/config/config.inc.php
sed -i "85i\ \ \ \ 'autologon'," /var/www/html/config/config.inc.php
sed -i "86i\ \ \ \ 'database_attachments'," /var/www/html/config/config.inc.php
sed -i "87i\ \ \ \ 'emoticons'," /var/www/html/config/config.inc.php
sed -i "88i\ \ \ \ 'filesystem_attachments'," /var/www/html/config/config.inc.php
sed -i "89i\ \ \ \ 'hide_blockquote'," /var/www/html/config/config.inc.php
sed -i "90i\ \ \ \ 'identity_select'," /var/www/html/config/config.inc.php
sed -i "91i\ \ \ \ 'jqueryui'," /var/www/html/config/config.inc.php
sed -i "92i\ \ \ \ 'markasjunk'," /var/www/html/config/config.inc.php
sed -i "93i\ \ \ \ 'new_user_dialog'," /var/www/html/config/config.inc.php
sed -i "94i\ \ \ \ 'newmail_notifier'," /var/www/html/config/config.inc.php
sed -i "95i\ \ \ \ 'password'," /var/www/html/config/config.inc.php
sed -i "29i\$config['syslog_id'] = 'webmail';"  /var/www/html/config/config.inc.php
sed -i "s/\$config\['support_url']\ =\ '';/\$config\['support_url']\ =\ 'http:\/\/mail.$domainame:808';/g" /var/www/html/config/config.inc.php
sed -i "s/\$config\['product_name']\ =\ 'Roundcube Webmail';/\$config\['product_name']\ =\ 'Web\ Mail\ Online';/g" /var/www/html/config/config.inc.php
#
systemctl enable httpd mariadb firewalld postfix dovecot saslauthd clamd@scan amavisd spamassassin clam-freshclam clamd@amavisd
systemctl status httpd mariadb firewalld postfix dovecot saslauthd clamd@scan amavisd spamassassin clam-freshclam clamd@amavisd -l
#
netstat -ntulp | grep -E ':4190|:110|:143|:993|:995|:465|:587|:25|:808|:10025|:10024'
#
echo '*********************************************************************************************************************************'
echo '* 1.congratulations! The script is executed!                                                                                    *'
echo '* 2.Please visit: http://YOUR_HOST_IP:808/postfixadmin/setup.php, Add a mailbox to the real administrator!                      *'
echo '* 3.After adding, please visit http://YOUR_HOST_IP/postfixadmin/login.php and enter the administrator email account to log in.  *'
echo '* 4.WEB version mail sending login address: http://YOUR_HOST_IP:808/                                                            *'
echo '* 5.The account and password for all programs are as follows:                                                                   *' 
echo '* -----------------------------------------------------------------------------------                                           *'
echo '* |  User: root     |  passwd: admin   |  Use: mysql                                 |                                          *'
echo '* -----------------------------------------------------------------------------------                                           *'
echo '* |  User: postfix  |  passwd: postfix |  Use: mysql                                 |                                          *' 
echo '* -----------------------------------------------------------------------------------                                           *'
echo '* |  User: webmail  |  passwd: webmail |  Use: mysql                                 |                                          *'
echo '* -----------------------------------------------------------------------------------                                           *'
echo '* |                 |  Passwd: admin   |  Use: http://IP:808/postfixadmin/setup.php  |                                          *'
echo '* -----------------------------------------------------------------------------------                                           *'
echo '* (In most cases, all passwords used: admin)                                                                                    *'
echo '* IP and domain name mailbox blacklist query URL：                                                                              *'
echo '*                                 https://www.spamhaus.org/lookup/                                                              *'
echo '*                                 https://mxtoolbox.com/                                                                        *'
echo '*                                 https://whatismyipaddress.com/blacklist-check                                                 *'
echo '*********************************************************************************************************************************'
#
