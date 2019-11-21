# MailSystemScript
Mail system fully automated installation script

#If you have any questions, please send an email to: nathan@netimed.cn

#System Operating envieonment
Cnetos 7.x

Redhat 7.x

#Feature description
1. Fully execute the script, just enter your own domain name (for example: netimed.cn)
2. After the execution is completed, the simple settings can be used in the production environment.
4. Support web page mailbox login and management
3. Domain name resolution settings, examples are as follows

     Mail.netimed.cn           A           ip address
     
     Smtp.netimed.cn           A           ip address
     
     Pop3.netimed.cn           A           ip address
     
     Imap.netimed.cn           A           ip address
     
     @                         MX          mail.netimed.cn
     

#Install Steps:
********************************************************************
 Warning:
 Please use user of root in Linux System to carried out script file
 
 Please make sure this is a brand new system(Important!!!)
********************************************************************
1.get master.sh file to centos 7.x system from https://github.com/Yewuqing/MailSystemScript

2.setting permission for master.sh

      chmod +x master.sh
      sh master.sh
      
  (just easy to finish it, Hum?)

3.Please waiting 30 mins for system can auto-finish it

4.Now view the web address http://IP:808/postfixadmin/setup.php,

   The first line of password is: admin (very unsafe, it is recommended to modify)
    
   Enter the administrator's email address in the second line (the mailbox needs to be available)
    
   Enter the administrator email password in the third line.
    
   Enter the administrator email password again in the third line.
    
    
5.View the web address http://IP:808/postfixadmin/login.php
  Enter your administrator's email address and password to log in. After successful login, you need to create a new email domain name and   users under the domain name.
  
6.After all settings are completed, modify the configuration file permissions to prevent hackers from brute force

      chmod  400 /var/www/html/postfixadmin/config.inc.php
      chmod  400 /var/www/html/installer/ -R
      chmod  400 /var/www/html/config/ -R
      chmod  400 /var/www/html/phpmyadmin/config.inc.php
      
7.Default password description

  There will be instructions after the script is installed.
  
  
