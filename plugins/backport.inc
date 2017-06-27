###
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# backport.inc
# $Revision: 1.226 $
#
# When a security flaw is discovered, many OS vendors do not update the product
# to its latest version, but tend to backport the patches instead. This module
# does a translation between the "fixed" (according to the vendor) products, and
# the latest version number.
#
# Credits: This excellent idea comes is from Laurent FACQ (facq@u-bordeaux.fr)
# and was initially designed to handle Debian. The idea has then been
# extended to a broader scope than Debian only.
#
# Usage :
#  new_banner = get_backport_banner(banner:orig_banner);
###

global_var backported;

backported = 0;

##
# Detects if a service's banner indicates security patches have been backported,
# and translates the version number to reflect this if necessary.  If it is
# determined that patches have been backported, the 'backported' global is
# set to 1.
#
# Some of the services covered by this function:
#   SSH
#   Apache HTTP Server and variants (e.g., Oracle HTTP Server, IBM HTTP Server)
#   Apache Tomcat
#   Sendmail
#
# @param banner banner of the network service being tested
#
# @return the translated "backport" banner, if it was determined patches have been backported,
#         'banner' if it was determined patches have not been backported,
#         'banner' if Report Paranoia is set to 'Paranoid',
##
function get_backport_banner(banner)
{
 local_var i, j,k,l,backported_versions, real_versions, rx_backported_versions, rx_real_versions, paranoia, str;

 backported = 0;
 paranoia = get_kb_item("global_settings/report_paranoia");
 if ( "Paranoid" >< paranoia ) return banner;

 i = 0;
 j = 0;
 k = 0;
 l = 0;

#
# Amazon Linux
#
backported_versions[i++] = "Apache/2.2.29 (Amazon) DAV/2 mod_ssl/2.2.15 OpenSSL/1.0.1k-fips";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon) DAV/2 mod_ssl/2.99.99 OpenSSL/1.99.99z-fips";

backported_versions[i++] = "Apache/2.4.12 (Amazon) mod_auth_tkt/2.1.0";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon) mod_auth_tkt/2.99.99";

# VULN-86434
backported_versions[i++] = "Apache/2.4.25 (Amazon) OpenSSL/1.0.1k-fips";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon) OpenSSL/1.99.99z-fips";

backported_versions[i++] = "Apache/2.4.25 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

# Amazon Linux AMI ALAS-2016-725
# https://alas.aws.amazon.com/ALAS-2016-725.html
backported_versions[i++] = "Apache/2.4.23 (Amazon) OpenSSL/1.0.1k-fips";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon) OpenSSL/1.99.99z-fips";

backported_versions[i++] = "Apache/2.4.23 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

# Amazon Linux AMI release 2016.03
backported_versions[i++] = "Apache/2.4.18 (Amazon) OpenSSL/1.0.1k-fips";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon) OpenSSL/1.99.99z-fips";

backported_versions[i++] = "Apache/2.4.18 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

backported_versions[i++] = "<title>Apache Tomcat/6.0.45";
real_versions[j++]       = "<title>Apache Tomcat/6.99.99";

backported_versions[i++] = "<title>Apache Tomcat/7.0.69";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

backported_versions[i++] = "<title>Apache Tomcat/8.0.35";
real_versions[j++]       = "<title>Apache Tomcat/8.99.99";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.15 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.11 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.6 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';


# Amazon Linux AMI release 2015.03
backported_versions[i++] = "Apache/2.2.31 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

backported_versions[i++] = "Apache/2.4.16 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

backported_versions[i++] = "<title>Apache Tomcat/7.0.62";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

backported_versions[i++] = "<title>Apache Tomcat/8.0.23";
real_versions[j++]       = "<title>Apache Tomcat/8.99.99";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.20 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.13 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.4 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2014.09
backported_versions[i++] = "Apache/2.2.29 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

backported_versions[i++] = "Apache/2.4.10 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

backported_versions[i++] = "<title>Apache Tomcat/6.0.43";
real_versions[j++]       = "<title>Apache Tomcat/6.99.99";

backported_versions[i++] = "<title>Apache Tomcat/8.0.20";
real_versions[j++]       = "<title>Apache Tomcat/8.99.99";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.20 .*\\(Red Hat 4\\.8\\.2-7\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.10 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.6 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2014.03
rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.9 .*\\(Red Hat 4\\.8\\.2-7\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2013.09
backported_versions[i++] = "Apache/2.2.26 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

backported_versions[i++] = "Apache/2.4.9 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.20 .*\\(Red Hat 4\\.6\\.3-2\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.7 .*\\(Red Hat 4\\.6\\.3-2\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2013.03
backported_versions[i++] = "Apache/2.2.25 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

backported_versions[i++] = "Apache/2.4.6 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.13 .*\\(Red Hat 4\\.6\\.2-2\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.4 .*\\(Red Hat 4\\.6\\.3-2\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2012.09
backported_versions[i++] = "Apache/2.2.23 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

backported_versions[i++] = "Apache/2.4.3 (Amazon)";
real_versions[j++]       = "Apache/2.4.99 (ConvertedAmazon)";

backported_versions[i++] = "<title>Apache Tomcat/6.0.36";
real_versions[j++]       = "<title>Apache Tomcat/6.99.99";

backported_versions[i++] = "<title>Apache Tomcat/7.0.37";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.4 .*\\(Red Hat 4\\.6\\.2-2\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2012.03
backported_versions[i++] = "<title>Apache Tomcat/7.0.32";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.13 .*\\(Red Hat 4\\.4\\.6-3\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

rx_backported_versions[k++] = 'PostgreSQL 9\\.1\\.5 .*\\(Red Hat 4\\.4\\.6-3\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';

# Amazon Linux AMI release 2011.03
backported_versions[i++] = "Apache/2.2.22 (Amazon)";
real_versions[j++]       = "Apache/2.2.99 (ConvertedAmazon)";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.9 .*\\(Red Hat 4\\.4\\.5-6\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

#
# Debian
#
# Security support for old versions is over

rx_backported_versions[k++] = '.*OpenSSH_3\\.4p1 Debian 1:3.4p1-1\\.woody\\.3';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.4p1-1.woody.3";


rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian';
rx_real_versions[l++] = 'SSH-2.0-OpenSSH_9.99p9 ConvertedDebian';


rx_backported_versions[k++] = '.*OpenSSH_3\\.6\\.1p2 Debian 1:3\\.6\\.1p2-3\\.sarge\\.1';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.6.1p2-3.sarge.1";

backported_versions[i++] = 'OpenSSH_3.8.1p1 Debian-8.sarge.4';
real_versions[j++]        = 'OpenSSH_9.9.99p1 ConvertedDebian';

backported_versions[i++] = 'OpenSSH_4.3p2 Debian-9etch';
real_versions[j++]        = 'OpenSSH_9.9.99p1 ConvertedDebian';

backported_versions[i++] = "Sendmail 8.12.3/8.12.3/Debian-6.6;";
real_versions[j++]   = "Sendmail 8.12.10/8.12.10/ConvertedDebian;";

backported_versions[i++] = "SSH-2.0-dropbear_0.45";  # Sarge
real_versions[j++]   = "SSH-2.0-dropbear_0.99";


#
# MacOS X
#

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2003-0693';
rx_real_versions[l++]   = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2003-0693";

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2004-0175';
rx_real_versions[l++]   = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2004-0175";
#
# AltLinux
#
rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p2-alt4';
rx_real_versions[l++]       = "SSH-2.0-OpenSSH_9.9.99-convertedAlt4";


#
# Cisco NAM
#
backported_versions[i++]   = "OpenSSH_4.4";
real_versions[j++]         = "OpenSSH_9.9.99";


#
# Dell iDRAC
#
backported_versions[i++]   = "dropbear_0.50";
real_versions[j++]         = "dropbear_99.999";

backported_versions[i++]   = "lighttpd/1.4.23";
real_versions[j++]         = "lighttpd/99.99.999";


#
# FreeBSD
#
rx_backported_versions[k++] = "OpenSSH.*FreeBSD.*(20030916|200[4-9])";
rx_real_versions[l++]       = "OpenSSH_3.7.1p2 (ConvertedFreeBSD)";

# FreeBSD 7.3
backported_versions[i++]   = "Apache/2.2.14 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 7.3)";

rx_backported_versions[k++] = "OpenSSH_5\.1p1 FreeBSD-";
rx_real_versions[l++]       = "OpenSSH_5.99 (ConvertedFreeBSD 7.3)";

# FreeBSD 7.4 (SSH banner is same as for 7.3)
backported_versions[i++]   = "Apache/2.2.17 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 7.4)";

# FreeBSD 8.0
backported_versions[i++]   = "Apache/2.2.13 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 8.0)";

rx_backported_versions[k++] = "OpenSSH_5\.2p1 FreeBSD-";
rx_real_versions[l++]       = "OpenSSH_5.99 (ConvertedFreeBSD 8.0)";

# FreeBSD 8.1
backported_versions[i++]   = "Apache/2.2.15 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 8.1)";

rx_backported_versions[k++] = "OpenSSH_5\.4p1 FreeBSD-";
rx_real_versions[l++]       = "OpenSSH_5.99 (ConvertedFreeBSD 8.1)";

# FreeBSD 8.2
#
# - SSH banner is like 8.1 (eg, SSH-2.0-OpenSSH_5.4p1 FreeBSD-20100308)
# - Apache banner is like 7.4 (eg, Server: Apache/2.2.17 (FreeBSD) mod_ssl/2.2.17 OpenSSL/0.9.8q DAV/2)

# FreeBSD 8.3
backported_versions[i++]   = "Apache/2.2.22 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 8.3)";

backported_versions[i++]   = "OpenSSH_5.4p1_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_5.99 (ConvertedFreeBSD 8.3)";

backported_versions[i++]   = "ProFTPD 1.3.4a ";
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD 8.3)";

# FreeBSD 8.4
backported_versions[i++]   = "Apache/2.2.24 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 8.4)";

backported_versions[i++]   = "Apache/2.4.16 (FreeBSD)"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD 8.4)";

backported_versions[i++]   = "OpenSSH_6.1_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_6.99 (ConvertedFreeBSD 8.4)";

backported_versions[i++]   = "ProFTPD 1.3.4c ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.5a "; # Patched
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD 8.4)";

# nb: same as in Fedora 20
backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

# FreeBSD 9.0
backported_versions[i++]   = "Apache/2.2.21 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 9.0)";

backported_versions[i++]   = "OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503";
real_versions[j++]         = "OpenSSH_5.99 (ConvertedFreeBSD 9.0 / 9.1)";

backported_versions[i++]   = "ProFTPD 1.3.3g ";
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD 9.0)";

# FreeBSD 9.1
backported_versions[i++]   = "Apache/2.2.23 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 9.1)";

# nb: same as in 9.0
#backported_versions[i++]   = "OpenSSH_5.8p2_hpn13v11 FreeBSD-";
#real_versions[j++]         = "OpenSSH_5.99 (ConvertedFreeBSD 9.1)";

backported_versions[i++]   = "ProFTPD 1.3.4b ";
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD 9.1)";

# FreeBSD 9.2
backported_versions[i++]   = "Apache/2.2.25 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD 9.2)";

# nb: same as in 9.0
backported_versions[i++]   = "OpenSSH_6.2_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_6.99 (ConvertedFreeBSD 9.2)";

# nb: same as in 10.0
backported_versions[i++]   = "ProFTPD 1.3.4d ";
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD)";

# FreeBSD 9.3
backported_versions[i++]   = "Apache/2.4.9 (FreeBSD)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD 9.3)";

backported_versions[i++]   = "OpenSSH_6.6.1_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_6.99 (ConvertedFreeBSD 9.3)";

backported_versions[i++]   = "ProFTPD 1.3.5 ";
real_versions[j++]         = "ProFTPD 1.3.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.54";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

# FreeBSD 10.0
backported_versions[i++]   = "Apache/2.2.26 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "Apache/2.4.6 (FreeBSD)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "OpenSSH_6.4_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_6.99 (ConvertedFreeBSD 10.0)";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.3\\.2 .+portbld.+compiled by FreeBSD';
rx_real_versions[l++]         = 'PostgreSQL 9.3.99 ConvertedFreeBSD 10.0';

# nb: same as with 9.2
#backported_versions[i++]   = "ProFTPD 1.3.4d ";
#real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

# nb: same as in FreeBSD 8.4
#backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
#real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

# FreeBSD 10.1
backported_versions[i++]   = "Apache/2.2.29 (FreeBSD)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "Apache/2.4.10 (FreeBSD)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "Apache/2.4.16 (FreeBSD)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "OpenSSH_6.6.1_hpn13v11 FreeBSD-";
real_versions[j++]         = "OpenSSH_6.99 (ConvertedFreeBSD 10.1)";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.4beta1 .+portbld.+compiled by FreeBSD';
rx_real_versions[l++]         = 'PostgreSQL 9.4.99 ConvertedFreeBSD 10.1';

rx_backported_versions[k++]   = 'PostgreSQL 9\\.3\\.9 .+portbld.+compiled by FreeBSD'; # Patched
rx_real_versions[l++]         = 'PostgreSQL 9.4.99 ConvertedFreeBSD 10';

backported_versions[i++]   = "ProFTPD 1.3.5 ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.5a "; # Patched
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.9/8.14.9";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.44";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# FreeBSD 10.3
backported_versions[i++]   = "Apache/2.4.16 (FreeBSD)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "Apache/2.4.23 (FreeBSD)"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFreeBSD)";

backported_versions[i++]   = "OpenSSH_7.2 FreeBSD-";
real_versions[j++]         = "OpenSSH_7.99 (ConvertedFreeBSD 10.3)";

backported_versions[i++]   = "Sendmail 8.15.2/8.15.2";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.59";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

# HP-UX
#
# eg, Server: Apache/2.0.58 HP-UX_Apache-based_Web_Server (Unix) DAV/2 PHP/5.2.0 mod_jk/1.2.19-dev
#     Server: Apache/2.0.59 HP-UX_Apache-based_Web_Server (Unix) DAV/2 mod_ssl/2.0.59 OpenSSL/0.9.8k
#     Server: Apache/2.2.15 HP-UX_Apache-based_Web_Server (Unix) mod_ssl/2.2.15 OpenSSL/0.9.8w DAV/2 PHP/5.2.17
rx_backported_versions[k++]  = "Apache/2\.0\.[0-9]+ +HP-UX_Apache-based_Web_Server";
rx_real_versions[l++]        = "Apache/2.999.999 (ConvertedHPUX)";

rx_backported_versions[k++]  = "Apache/2\.2\.[0-9]+ +HP-UX_Apache-based_Web_Server";
rx_real_versions[l++]        = "Apache/2.2.99 (ConvertedHPUX)";


# IBM's Apache
#
backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.4 Apache/1.3.20";
real_versions[j++]         = "Apache/1.3.28 (ConvertedIBM)";

rx_backported_versions[k++] = "IBM_HTTP_SERVER/2\.0\.47\.[1-9]\.";
rx_real_versions[l++]     = "Apache/2.999.999 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.0\.[0-9][^ ]* Apache/2\.0\.47";
rx_real_versions[l++]         = "Apache/2.999.999 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.0\.2\.[0-9]+[^ ]* Apache/2\.0\.47";
rx_real_versions[l++]         = "Apache/2.999.99 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.1\.0\.[0-9]+[^ ]* Apache/2\.0\.47";
rx_real_versions[l++]         = "Apache/2.999.999 (ConvertedIBM)";

backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.6 Apache/1.3.20";
real_versions[j++]         = "Apache/1.3.29 (ConvertedIBM)";

# Checkpoint IPSO OS
backported_versions[i++]   = "CPWS/2.2.0 (Unix) mod_ssl/2.2.0 OpenSSL/0.9.8b DAV/2";
real_versions[j++]         = "CPWS/2.2.0 (ConvertedUnix) mod_ssl/2.99.99 OpenSSL/0.99.99z DAV/2";

# potato
backported_versions[i++]   = "ProFTPD 1.2.0pre10 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.2.0 (ConvertedDebian 2.2)";

# woody
backported_versions[i++]   = "Apache/1.3.26 (Unix) Debian GNU/Linux";
real_versions[j++]         = "Apache/1.3.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.2.5rc1 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.2.5 (ConvertedDebian)";

backported_versions[i++]   = "<title>Apache Tomcat/4.0.3";
real_versions[j++]         = "<title>Apache Tomcat/4.0.99";

# sarge
backported_versions[i++]   = "Apache/2.0.54 (Debian)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedDebian)";
backported_versions[i++]   = "Apache/2.0.55 (Debian)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.2.10 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.2.10 (ConvertedDebian 3.1)";

backported_versions[i++]   = "<title>Apache Tomcat/4.1.31";
real_versions[j++]         = "<title>Apache Tomcat/4.1.99";

# etch
backported_versions[i++]   = "Apache/2.2.3 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.3.0 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.0 (ConvertedDebian 4.0)";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.20";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# lenny
backported_versions[i++]   = "Apache/2.2.9 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

backported_versions[i++] = "Apache/1.3.34 (Debian)";
real_versions[j++]       = "Apache/1.3.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.3.1 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.1 (ConvertedDebian 5.0)";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.26";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.1p1 Debian-5';
rx_real_versions[l++]         = "SSH-2.0-OpenSSH_9.9.99 ConvertedDebian";

# squeeze
backported_versions[i++]   = "Apache/2.2.16 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.3.3a Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.3a (ConvertedDebian 6.0)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.28";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.5p1 Debian-6';
rx_real_versions[l++]         = "SSH-2.0-OpenSSH_9.9.99 ConvertedDebian";

rx_backported_versions[k++] = 'Sendmail 8\\.14\\.3/8\\.14\\.3/Debian-9\\.4';
rx_real_versions[l++]       = 'Sendmail 8.14.3/8.14.3/ConvertedDebian 6';

rx_backported_versions[k++]   = 'PostgreSQL 8\\.4\\.13 .*\\(Debian 4\\.4\\.5-8\\)';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedDebian';

# wheezy
backported_versions[i++]   = "Apache/2.2.22 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.3.4a Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.4a (ConvertedDebian 7.0)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.35";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.45"; # patched
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.28";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]   = '.*OpenSSH_6\\.0p1 Debian-4';
rx_real_versions[l++]         = "SSH-2.0-OpenSSH_9.9.99 ConvertedDebian";

rx_backported_versions[k++] = 'Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-4';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedDebian 7';

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.9 .*\\(Debian 4\\.7\\.2-5\\)';
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedDebian';

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.22 .*\\(Debian 4\\.7\\.2-5\\)'; # patched
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedDebian';

# jessie
backported_versions[i++]   = "Apache/2.4.10 (Debian)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedDebian)";

backported_versions[i++]   = "ProFTPD 1.3.5 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.5 (ConvertedDebian 8.0)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.45";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.56 (Debian)";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99 (ConvertedDebian)";

backported_versions[i++]   = "<title>Apache Tomcat/8.0.14 (Debian)";
real_versions[j++]         = "<title>Apache Tomcat/8.0.99 (ConvertedDebian)";

rx_backported_versions[k++]   = '.*OpenSSH_6\\.7p1 Debian-5';
rx_real_versions[l++]         = 'SSH-2.0-OpenSSH_9.9.99 ConvertedDebian';

backported_versions[i++] = 'Sendmail 8.14.4/8.14.4/Debian-8';
real_versions[j++]       = 'Sendmail 8.14.4/8.14.4/ConvertedDebian 8';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.[18] .*\\(Debian 4\\.9\\.2-10\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedDebian';

# sid / testing
backported_versions[i++]    = "Apache/2.2.22 (Debian) PHP/5.3.3-7 + squeeze8 withSuhosinPatch mod_ssl/2.2.22 OpenSSL/0.9.8o";
real_versions[j++]          = "Apache/2.2.99 (ConvertedDebian) PHP/5.3.99-9 + squeeze8 withSuhosinPatch mod_ssl/2.2.99 OpenSSL/0.9.99z";

# Ubuntu 4.10
backported_versions[i++]   = "Apache/2.0.50 (Ubuntu)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_3\\.8\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 5.04
backported_versions[i++]   = "Apache/2.0.53 (Ubuntu)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_3\\.9p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 5.10
backported_versions[i++]   = "Apache/2.0.54 (Ubuntu)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++] = 'Sendmail 8\\.13\\.4/8\\.13\\.4/Debian-3ubuntu0(\\.[0-9]+)?;';
rx_real_versions[l++]       = "Sendmail 8.13.4/8.13.4/ConvertedUbuntu 5.10";

# Ubuntu 6.06 and 6.10
backported_versions[i++]   = "Apache/2.0.55 (Ubuntu)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.2p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++] = '.*Sendmail 8\\.13\\.5\\.20060308/8\\.13\\.5/Debian-3ubuntu1(\\.[0-9]+)?;';
rx_real_versions[l++]       = "Sendmail 8.13.5/8.13.5/ConvertedUbuntu 6.06 / 6.10";

backported_versions[i++]   = "ProFTPD 1.2.10 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.2.10 (ConvertedUbuntu 6.06)";

# Ubuntu 7.04
backported_versions[i++]   = "Apache/2.2.3 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

#rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian.*ubuntu';
#rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 7.10
backported_versions[i++]   = "Apache/2.2.4 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.6p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 8.04
backported_versions[i++]   = "Apache/2.2.8 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.7p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++]   = '.*Sendmail 8\\.14\\.2/8\\.14\\.2/Debian-2build1(\\.[0-9]+)?;';
rx_real_versions[l++]         = 'Sendmail 8.14.2/8.14.2/ConvertedUbuntu 8.04';

rx_backported_versions[k++]   = 'PostgreSQL 8\\.3\\.21 .*\\(Ubuntu 4\\.2\\.4-1ubuntu4\\).*';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedUbuntu';

rx_backported_versions[k++]   = 'PostgreSQL 8\\.4\\.10 .*\\(Ubuntu 4\\.2\\.4-1ubuntu4\\), 64-bit';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedUbuntu';

backported_versions[i++]   = "ProFTPD 1.3.1 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.1 (ConvertedUbuntu 8.04)";

# Ubuntu 8.10
backported_versions[i++]   = "Apache/2.2.9 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 9.04
backported_versions[i++]   = "Apache/2.2.11 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 9.10
backported_versions[i++]    = "Apache/2.2.12 (Ubuntu)";
real_versions[j++]          = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]       = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.20";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Ubuntu 10.04
backported_versions[i++]    = "Apache/2.2.14 (Ubuntu)";
real_versions[j++]          = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.3p1 Debian.*ubuntu';
rx_real_versions[l++]       = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.4\\.(14|22) .*\\(Ubuntu 4\\.4\\.3-4ubuntu5\\.1\\).*';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedUbuntu';

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.3/8\\.14\\.3/Debian-9\\.1ubuntu1(\\.[0-9]+)?;';
rx_real_versions[l++]       = "Sendmail 8.14.3/8.14.3/ConvertedUbuntu 10.04";

backported_versions[i++]   = "ProFTPD 1.3.2c Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.2c (ConvertedUbuntu 10.04)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.24";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Ubuntu 10.10
backported_versions[i++]   = "Apache/2.2.16 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.5p1 Debian.*ubuntu';
rx_real_versions[l++]         = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

backported_versions[i++]   = "ProFTPD 1.3.2e Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.2e (ConvertedUbuntu 10.10)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.28";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Ubuntu 11.04
backported_versions[i++]   = "Apache/2.2.17 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.8p1 Debian.*ubuntu';
rx_real_versions[l++]         = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++]   = 'PostgreSQL 8\\.14\\.4 .*\\(Ubuntu/Linaro 4\\.5\\.2-8ubuntu4\\).*';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedUbuntu';

rx_backported_versions[k++]   = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-9\\.1ubuntu1(\\.[0-9]+)?;';
rx_real_versions[l++]         = "Sendmail 8.14.4/8.14.4/ConvertedUbuntu 11.04";

backported_versions[i++]   = "ProFTPD 1.3.3d Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.3d (ConvertedUbuntu 11.04)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.28";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Ubuntu 11.10
backported_versions[i++]   = "Apache/2.2.20 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.8p1 Debian.*ubuntu';
rx_real_versions[l++]         = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++]   = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-2ubuntu2(\\.[0-9]+)?;';
rx_real_versions[l++]         = "Sendmail 8.14.4/8.14.4/Converted Ubuntu 11.10";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.3\\.23 .*\\(Ubuntu/Linaro 4\\.2\\.4-1ubuntu3\\).*';
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedUbuntu";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.6 .*\\(Ubuntu/Linaro 4\\.6\\.1-9ubuntu3\\).*';
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedUbuntu";

backported_versions[i++]   = "ProFTPD 1.3.4rc2 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.4rc2 (ConvertedUbuntu 11.10)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.32";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Ubuntu 12.04
backported_versions[i++]   = "Apache/2.2.22 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++]   = '.*OpenSSH_5\\.9p1 Debian.*ubuntu';
rx_real_versions[l++]         = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

backported_versions[i++]   = "ProFTPD 1.3.4a Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.4a (ConvertedUbuntu 12.04)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.35";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.6 .*\\(Ubuntu/Linaro 4\\.6\\.3-1ubuntu5\\).*';
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedUbuntu";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-2ubuntu2(\\.[0-9]+)?;';
rx_real_versions[l++]       = "Sendmail 8.14.4/8.14.4/ConvertedUbuntu 12.04";

# Ubuntu 12.10
rx_backported_versions[k++]  = '.*OpenSSH_6\\.0p1 Debian.*ubuntu';
rx_real_versions[l++]        = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

backported_versions[i++]   = "<title>Apache Tomcat/7.0.30";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.1\\.6 .*\\(Ubuntu/Linaro 4\\.7\\.2-2ubuntu1\\).*';
rx_real_versions[l++]        = "PostgreSQL 9.99.99 ConvertedUbuntu";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-2\\.1ubuntu2(\\.[0-9]+)?;';
rx_real_versions[l++]       = "Sendmail 8.14.4/8.14.4/ConvertedUbuntu 12.10";

# Ubuntu 13.04
# The Apache banner matches that of Ubuntu 12.04

rx_backported_versions[k++] = '.*OpenSSH_6\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

# The Tomcat6 banner matches that of Ubuntu 12.04

backported_versions[i++]   = "<title>Apache Tomcat/7.0.35";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++] = 'PostgreSQL 9\\.1\\.9 .*\\(Ubuntu/Linaro 4\\.7\\.2-22ubuntu5\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

# The Sendmail banner matches that of Ubuntu 12.10

# The ProFTPD banner matches that of Ubuntu 12.04

# Ubuntu 13.10
backported_versions[i++]   = "Apache/2.4.6 (Ubuntu)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++]  = '.*OpenSSH_6\\.2p2 Ubuntu-6';
rx_real_versions[l++]        = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

backported_versions[i++]   = "ProFTPD 1.3.5rc3 Server (Debian)";
real_versions[j++]         = "ProFTPD 1.3.5rc3 (ConvertedUbuntu 13.10)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.37";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.42";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-2\\.1ubuntu4(\\.[0-9]+)?;';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedUbuntu 13.10';

rx_backported_versions[k++] = 'PostgreSQL 9\\.1\\.10 .*\\(Ubuntu/Linaro 4\\.8\\.1-10ubuntu7\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

# Ubuntu 14.04
backported_versions[i++]    = "Apache/2.4.7 (Ubuntu)";
real_versions[j++]          = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = 'OpenSSH_6\\.6p1 Ubuntu-2';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'OpenSSH_6\\.6\\.1p1 Ubuntu-2';         # patched
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

backported_versions[i++]    = "<title>Apache Tomcat/6.0.39";
real_versions[j++]          = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]    = "<title>Apache Tomcat/7.0.52 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-4\\.1ubuntu1(\\.[0-9]+)?;';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedUbuntu 14.04';

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.4 .*\\(Ubuntu 4\\.8\\.2-16ubuntu6\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

# Ubuntu 14.10
backported_versions[i++]    = "Apache/2.4.10 (Ubuntu)";
real_versions[j++]          = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = 'OpenSSH_6\\.6\\.1p1 Ubuntu-8';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4beta3 .*\\(Ubuntu 4\\.9\\.1-16ubuntu6\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.4 .*\\(Ubuntu 4\\.9\\.1-16ubuntu6\\).*'; # patched
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

backported_versions[i++]    = "ProFTPD 1.3.5 Server (Debian)";
real_versions[j++]          = "ProFTPD 1.3.5 (ConvertedUbuntu 14.10)";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-7;';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedUbuntu 14.10';

backported_versions[i++]    = "<title>Apache Tomcat/6.0.41";
real_versions[j++]          = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]    = "<title>Apache Tomcat/7.0.55 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

# Ubuntu 15.04
backported_versions[i++]    = "Apache/2.4.10 (Ubuntu)";
real_versions[j++]          = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_6\\.7p1 Ubuntu-5ubuntu1';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.1 .*\\(Ubuntu 4\\.9\\.2-10ubuntu5\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.5 .*\\(Ubuntu 4\\.9\\.2-10ubuntu13\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

backported_versions[i++]    = "ProFTPD 1.3.5 Server (Debian)";
real_versions[j++]          = "ProFTPD 1.3.5 (ConvertedUbuntu 15.04)";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.4/8\\.14\\.4/Debian-8;';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedUbuntu 15.04';

backported_versions[i++]    = "<title>Apache Tomcat/6.0.41";
real_versions[j++]          = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]    = "<title>Apache Tomcat/7.0.56 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

# Ubuntu 15.10
backported_versions[i++]    = "Apache/2.4.12 (Ubuntu)";
real_versions[j++]          = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_6\\.9p1 Ubuntu-2';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.5 .*\\(Ubuntu 5\\.1\\.1-21ubuntu2\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.4\\.8 .*\\(Ubuntu 5\\.2\\.1-22ubuntu2\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

backported_versions[i++]    = "ProFTPD 1.3.5 Server (Debian)";
real_versions[j++]          = "ProFTPD 1.3.5 (ConvertedUbuntu 15.10)";

rx_backported_versions[k++] = '.*Sendmail 8\\.14\\.9/8\\.14\\.9/Debian-4;';
rx_real_versions[l++]       = 'Sendmail 8.14.4/8.14.4/ConvertedUbuntu 15.10';

backported_versions[i++]    = "<title>Apache Tomcat/7.0.64 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

backported_versions[i++]    = "<title>Apache Tomcat/8.0.26 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/8.0.99 (ConvertedUbuntu)";

# Ubuntu 16.04
backported_versions[i++]    = "Apache/2.4.18 (Ubuntu)"; # also Ubuntu 16.10
real_versions[j++]          = "Apache/2.4.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_7\\.2p2 Ubuntu-4';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.5\\.2 .*\\(Ubuntu 5\\.3\\.1-13ubuntu3\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

backported_versions[i++]    = "ProFTPD 1.3.5a Server (Debian)"; # also Ubuntu 16.10
real_versions[j++]          = "ProFTPD 1.3.5a (ConvertedUbuntu 16.04)";

rx_backported_versions[k++] = '.*Sendmail 8\\.15\\.2/8\\.15\\.2/Debian-3;';
rx_real_versions[l++]       = 'Sendmail 8.15.2/8.15.2/ConvertedUbuntu 16.04';

backported_versions[i++]    = "<title>Apache Tomcat/7.0.68 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

backported_versions[i++]    = "<title>Apache Tomcat/8.0.32 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/8.0.99 (ConvertedUbuntu)";

# Ubuntu 16.10
rx_backported_versions[k++] = '.*OpenSSH_7\\.3p1 Ubuntu-1';
rx_real_versions[l++]       = 'SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu';

rx_backported_versions[k++] = 'PostgreSQL 9\\.5\\.4 .*\\(Ubuntu 6\\.1\\.1-11ubuntu12\\).*';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedUbuntu';

rx_backported_versions[k++] = '.*Sendmail 8\\.15\\.2/8\\.15\\.2/Debian-4;';
rx_real_versions[l++]       = 'Sendmail 8.15.2/8.15.2/ConvertedUbuntu 16.10';

backported_versions[i++]    = "<title>Apache Tomcat/7.0.72 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99 (ConvertedUbuntu)";

backported_versions[i++]    = "<title>Apache Tomcat/8.0.37 (Ubuntu)";
real_versions[j++]          = "<title>Apache Tomcat/8.0.99 (ConvertedUbuntu)";

# ZyXEL
backported_versions[i++]   = "SSH-1.5-1.0.0";
real_versions[j++]         = "SSH-1.5-9.9.9";

# QNX
backported_versions[i++]   = "OpenSSH_5.2 QNX_Secure_Shell";
real_versions[j++]         = "OpenSSH_9.9.99";


#
# Red Hat and others backports fixes - we can't always rely on the version
# number
#

# Red Hat EL (S/W/D)
backported_versions[i++]   = "Apache/2.2.27 (Unix) mod_ssl/2.2.27 OpenSSL/1.0.1e-fips PHP/5.3.28";
real_versions[j++]         = "Apache/2.2.999 (Unix) mod_ssl/2.2.999 OpenSSL/1.0.999e-fips PHP/5.3.999";

# Red Hat 8.0 and 9.0
backported_versions[i++]   = "Apache/2.0.40 (Red Hat Linux)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedRedHat)";

# ES2.1
backported_versions[i++]   = "Apache/1.3.27 (Unix)  (Red-Hat/Linux)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedRedHat)";

backported_versions[i++]   = "OpenSSH_3.1p1";
real_versions[j++]         = "OpenSSH_9.9.99";

# ES3
backported_versions[i++]   = "Apache/2.0.46 (Red Hat)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.0.46 (CentOS)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedCentOS)";


backported_versions[i++]   = "OpenSSH_3.6.1p2";
real_versions[j++]         = "OpenSSH_9.9.99";

# ES4
backported_versions[i++]   = "Apache/2.0.52 (Red Hat)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.0.52 (CentOS)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedCentOS)";

backported_versions[i++]   = "OpenSSH_3.9p1";
real_versions[j++]         = "OpenSSH_9.9.99";

# ES5
backported_versions[i++]   = "Apache/2.2.3 (Red Hat)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

# nb: RedHat's JBoss Enterprise Web Server 1.0.2 / JBoss Enterprise
#     Web Server Plus 1.0.2 include a version of Apache.
backported_versions[i++]   = "Apache/2.2.17 (Red Hat Enterprise Web Server)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.2.3 (CentOS)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedCentOS)";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.23";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "OpenSSH_4.3";
real_versions[j++]         = "OpenSSH_9.9.99";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.1\\.23 .*\\(Red Hat 4\\.1\\.2-52\\)';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedCentOS';

# EL6
backported_versions[i++]   = "Apache/2.2.15 (Red Hat)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

# nb: RedHat's JBoss Enterprise Web Server 1.0.2 / JBoss Enterprise
#     Web Server Plus 1.0.2 include a version of Apache.
backported_versions[i++]   = "Apache/2.2.17 (Red Hat Enterprise Web Server)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.24";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "OpenSSH_5.3";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/2.2.15 (CentOS)";
real_versions[j++]         = "Apache/2.2.99 (CentOS)";

backported_versions[i++]   = 'OpenSSL/1.0.1e-fips';
real_versions[j++]         = 'OpenSSL/1.0.1zzzz-fips';

backported_versions[i++]   = 'X-Powered-By: PHP/5.3.3';
real_versions[j++]         = 'X-Powered-By: PHP/5.9.99';

backported_versions[i++]   = 'Apache/2.2.26 (Red Hat Enterprise Web Server)';
real_versions[j++]         = 'Apache/2.2.99 (ConvertedRedHat)';

rx_backported_versions[k++]   = "PostgreSQL 8\.4\.20 .*\(Red Hat 4\.4\.7-17\)";
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedCentOS";

# EL7
backported_versions[i++]   = "Apache/2.4.6 (Red Hat)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";
backported_versions[i++]   = "Apache/2.4.6 (Red Hat Enterprise Linux)"; # RHEL 7.1
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.4.6 (CentOS)";
real_versions[j++]         = "Apache/2.4.6 (ConvertedCentOS)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.42";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.54"; # patch
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "OpenSSH_6.4";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "OpenSSH_6.6.1"; # patch
real_versions[j++]         = "OpenSSH_9.9.99";

rx_backported_versions[k++]   = "PostgreSQL 9\.2\.7 .*\(Red Hat 4\.8\.2-13\)";
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedRedHat";

rx_backported_versions[k++]   = "PostgreSQL 9\.2\.7 .*\(Red Hat 4\.8\.2 ";
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedCentOS";

rx_backported_versions[k++]   = "PostgreSQL 9\.2\.15 .*\(Red Hat 4\.8\.5-4\)"; # patch
rx_real_versions[l++]         = "PostgreSQL 9.99.99 ConvertedRedHat";

# 6.2.6 RedHat Satellite Server running on top of RedHat Enterprise Linux 7.3.
backported_versions[i++] = "WEBrick/1.3.1 (Ruby/2.0.0/2014-11-13) OpenSSL/1.0.1e";
real_versions[j++]       = "OpenSSL/1.9.99z ConvertedRedHat";

# 6.2.8 RedHat Satellite Server running on top of RedHat Enterprise Linux 7.
backported_versions[i++] = "WEBrick/1.3.1 (Ruby/2.0.0/2015-12-16) OpenSSL/1.0.1e";
real_versions[j++]       = "OpenSSL/1.9.99z ConvertedRedHat";

# Puppet agent 3.8.7 running on top of CentOS 6.8.
# also Puppet Foreman Proxy 1.11.4 on RHEL 6.8.
backported_versions[i++] = "WEBrick/1.3.1 (Ruby/1.8.7/2013-06-27) OpenSSL/1.0.1e";
real_versions[j++]       = "OpenSSL/1.9.99z ConvertedRedHat";

# Scientific Linux 3
backported_versions[i++]    = "Apache/2.0.46 (Scientific Linux)";
real_versions[j++]          = "Apache/2.999.999 (ConvertedScientificLinux)";

# Scientific Linux 4
backported_versions[i++]    = "Apache/2.0.52 (Scientific Linux)";
real_versions[j++]          = "Apache/2.999.999 (ConvertedScientificLinux)";

backported_versions[i++]    = "OpenSSH_3.9p1";
real_versions[j++]          = "OpenSSH_9.9.99";

# Scientific Linux 5
backported_versions[i++]    = "Apache/2.2.3 (Scientific Linux)";
real_versions[j++]      = "Apache/2.2.99 (ConvertedScientificLinux)";

backported_versions[i++]    = "OpenSSH_4.3";
real_versions[j++]          = "OpenSSH_9.9.99";

backported_versions[i++]    = "<title>Apache Tomcat/5.5.23";
real_versions[j++]          = "<title>Apache Tomcat/5.5.99";

rx_backported_versions[k++] = 'PostgreSQL 8\\.1\\.23 .*\\(Red Hat 4\\.1\\.2-52\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

# Scientific Linux 6
backported_versions[i++]    = "Apache/2.2.15 (Scientific Linux)";
real_versions[j++]      = "Apache/2.2.99 (ConvertedScientificLinux)";

backported_versions[i++]    = "OpenSSH_5.3";
real_versions[j++]          = "OpenSSH_9.9.99";

backported_versions[i++]    = "<title>Apache Tomcat/6.0.24";
real_versions[j++]          = "<title>Apache Tomcat/6.0.99";

rx_backported_versions[k++] = 'PostgreSQL 8\\.4\\.13 .*\\(Red Hat 4\\.4\\.6-4\\)';
rx_real_versions[l++]       = 'PostgreSQL 8.99.99';

# Scientific Linux 7
backported_versions[i++]    = "Apache/2.4.6 (Scientific Linux)";
real_versions[j++]      = "Apache/2.4.99 (ConvertedScientificLinux)";

backported_versions[i++]    = "OpenSSH_6.4";
real_versions[j++]          = "OpenSSH_9.9.99";

backported_versions[i++]    = "<title>Apache Tomcat/7.0.42";
real_versions[j++]          = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.7 .*\\(Red Hat 4\\.8\\.2-16\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99';


# Oracle
backported_versions[i++]   = "Oracle HTTP Server Powered by Apache/1.3.19";
real_versions[j++]         = "Oracle HTTP Server Powered by Apache/1.3.99 (Converted)";

# Oracle again
backported_versions[i++]   = "Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_perl/1.22";
real_versions[j++]         = "Apache/1.3.99 (Win32) ApacheJServ/9.9 mod_perl/9.99";

# Oracle Linux 7.1
backported_versions[i++]   = "Apache/2.4.6 ()";
real_versions[j++]     = "Apache/2.4.99 (ConvertedOracle)";

# Oracle Linux 6
backported_versions[i++]   = "Apache/2.2.15 (Oracle)";
real_versions[j++]     = "Apache/2.2.99 (ConvertedOracle)";

# Oracle Enterprise Linux 5
backported_versions[i++]   = "Apache/2.2.3 (Oracle)";
real_versions[j++]     = "Apache/2.2.99 (ConvertedOracle)";

# Oracle Unbreakable Linux 4
backported_versions[i++]   = "Apache/2.0.52 (Oracle)";
real_versions[j++]     = "Apache/2.999.999 (ConvertedOracle)";

# Oracle Solaris
backported_versions[i++]   = "Apache/2.0.63 (Unix)";
real_versions[j++]     = "Apache/2.999.999 (ConvertedSolaris)";

# CPanel
rx_backported_versions[k++] = "Apache/1\.3\.37 \(Unix\).*mod_auth_passthrough/1\.8.*mod_bwlimited/1\.4.*mod_ssl/2\.8\.28";
rx_real_versions[l++]        = "Apache/1.9.99";


backported_versions[i++]   = "OpenSSH_3.9p1";
real_versions[j++]         = "OpenSSH_9.9.99";


# SuSE 8.0, Red Hat 8.0
backported_versions[i++]   = "OpenSSH_3.4p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/4.0.1";
real_versions[j++]         = "<title>Apache Tomcat/4.0.99";

# SuSE 8.x, Red Hat 9.0
backported_versions[i++]   = "OpenSSH_3.5p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/4.0.4";
real_versions[j++]         = "<title>Apache Tomcat/4.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/4.1.18";
real_versions[j++]         = "<title>Apache Tomcat/4.1.99";

# SuSE 9.0
backported_versions[i++]   = "Apache/2.0.48 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.7.1p2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/1.3.28 (Linux/SUSE)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/4.1.27";
real_versions[j++]         = "<title>Apache Tomcat/4.1.99";

# SuSE 9.1
backported_versions[i++]   = "Apache/2.0.49 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.8p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.0.19";
real_versions[j++]         = "<title>Apache Tomcat/5.0.99";

# SuSE 9.2
backported_versions[i++]   = "Apache/2.0.50 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/5.0.27";
real_versions[j++]         = "<title>Apache Tomcat/5.0.99";

# SSH -> Same as ES4

# SuSE 9.3
backported_versions[i++]   = "Apache/2.0.53 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/5.0.30";
real_versions[j++]         = "<title>Apache Tomcat/5.0.99";

# SLES 9 SP4

backported_versions[i++]   = "OpenSSH_4.1";
real_versions[j++]         = "OpenSSH_9.9.99";

# SSH -> Same as ES4

# SuSE 10.0
backported_versions[i++]   = "Apache/2.0.54 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.1p1";
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.1
backported_versions[i++]   = "Apache/2.2.0 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.2p1";
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.2
backported_versions[i++]   = "Apache/2.2.3 (Linux/SuSE)";  # also SLES10
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.4p1";
real_versions[j++]         = "OpenSSH_9.9.99";

# SLES 10 SP2

backported_versions[i++]   = "OpenSSH_4.2";
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.3
backported_versions[i++]   = "Apache/2.2.4 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.6";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "OpenSSH_4.6p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.23";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# SuSE 10.4

backported_versions[i++]   = "Apache/2.2.3 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 *ConvertedSUSE)";

backported_versions[i++]   = "SSH-1.99-OpenSSH_5.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.1\\.23 .*\\(SUSE Linux\\)';
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedSUSE';

# SuSE 11
backported_versions[i++]   = "Apache/2.2.8 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.0";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.16";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# SuSE 11 SP1
backported_versions[i++]   = "Apache/2.2.10 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "Apache/2.2.12 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.18";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.3\\.20 .*\\(SUSE Linux\\)';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedSUSE';

# SuSE 11 SP3
backported_versions[i++]   = "SSH-2.0-OpenSSH_6.2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++] = "<title>Apache Tomcat/6.0.41";
real_versions[j++]       = "<title>Apache Tomcat/6.0.99";

# SuSE 12
backported_versions[i++]   = "SSH-2.0-OpenSSH_6.6.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/2.4.10 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.55";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.68"; # patch
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.3\\.5 .*\\(SUSE Linux\\)'; # Fresh install
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedSUSE';

rx_backported_versions[k++]   = 'PostgreSQL 9\\.3\\.6 .*\\(SUSE Linux\\)'; # patch
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedSUSE';

rx_backported_versions[k++]   = 'PostgreSQL 9\\.3\\.11 .*\\(SUSE Linux\\)'; # patch
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedSUSE';

# openSUSE 11.0
backported_versions[i++] = 'Sendmail 8.14.3/8.14.3/SuSE Linux 0.8';
real_versions[j++]       = "Sendmail 8.14.3/8.14.3/ConvertedOpenSUSE 11.0";

# openSuSE 11.1
backported_versions[i++]   = "Apache/2.2.10 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++] = 'Sendmail 8.14.3/8.14.3/SuSE Linux 0.8';
real_versions[j++]       = "Sendmail 8.14.3/8.14.3/ConvertedOpenSUSE 11.1";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.18";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# openSUSE 11.2
backported_versions[i++] = 'Sendmail 8.14.3/8.14.3/SuSE Linux 0.8';
real_versions[j++]       = "Sendmail 8.14.3/8.14.3/ConvertedOpenSUSE 11.2 Milestone 2";

# openSuSE 11.4
backported_versions[i++]   = "Apache/2.2.17 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.8";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.32";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "Sendmail 8.14.4/8.14.4/SuSE Linux 0.8";
real_versions[j++]         = "SendMail 8.14.4/8.14.4/ConvertedOpenSUSE 11.4";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.0\\.10 .*\\(SUSE Linux\\) 4\\.5\\.1';
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 11.4';

# openSuSE 12.1
backported_versions[i++]   = "Apache/2.2.21 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.33";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "Sendmail 8.14.5/8.14.5/SuSE Linux 0.8";
real_versions[j++]         = "Sendmail 8.14.5/8.14.5/ConvertedOpenSUSE 12.1";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.1\\.6 .*\\(SUSE Linux\\) 4\\.6\\.2';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 12.1';

# openSuSE 12.2
backported_versions[i++]   = "Apache/2.2.22 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.27";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "SSH-2.0-OpenSSH_6.0";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Sendmail 8.14.5/8.14.5/SuSE Linux 0.8";
real_versions[j++]         = "Sendmail 8.14.5/8.14.5/ConvertedOpenSUSE 12.2";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.1\\.6 .*\\(SUSE Linux\\) 4\\.7\\.1';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 12.2';

# openSuSE 12.3
backported_versions[i++]   = "Apache/2.2.22 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "Apache/2.2.29 (Linux/SUSE)"; # Patched
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.35";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.42"; # Patched
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "SSH-2.0-OpenSSH_6.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++] = "Sendmail 8.14.5/8.14.5/SuSE Linux 0.8";
real_versions[j++]       = "Sendmail 8.14.5/8.14.5/ConvertedOpenSUSE 12.3";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.3 .*\\(SUSE Linux\\) 4\\.7\\.2';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 12.3';

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.7 .*\\(SUSE Linux\\) 4\\.7\\.2'; # Patched
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 12.3';

# openSuSE 13.1
backported_versions[i++]   = "Apache/2.4.6 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.42";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "SSH-2.0-OpenSSH_6.2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++] = "Sendmail 8.14.7/8.14.7/SuSE Linux 0.8";
real_versions[j++]       = "Sendmail 8.14.7/8.14.7/ConvertedOpenSUSE 13.1";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.4 .*\\(SUSE Linux\\) 4\\.8\\.1';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 13.1';

# openSuSE 13.2
backported_versions[i++]   = "Apache/2.4.10 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedSuSE)";

backported_versions[i++]   = "Apache Tomcat/7.0.55";
real_versions[j++]         = "Apache Tomcat/7.0.99";

backported_versions[i++]   = "SSH-2.0-OpenSSH_6.6.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++] = "Sendmail 8.14.9/8.14.9/SuSE Linux 0.8";
real_versions[j++]       = "Sendmail 8.14.9/8.14.9/ConvertedOpenSUSE 13.2";

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.5 .*\\(SUSE Linux\\) 4\\.8\\.3';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 13.2';

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.11 .*\\(SUSE Linux\\) 4\\.8\\.3'; # Patched
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 13.2';

# openSuSE 42.1 (Leap)
backported_versions[i++]   = "Apache Tomcat/8.0.23";
real_versions[j++]         = "Apache Tomcat/8.0.99";

backported_versions[i++]   = "Apache Tomcat/8.0.32";
real_versions[j++]         = "Apache Tomcat/8.0.99";

backported_versions[i++]   = "Apache/2.4.16 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedSuSE)";

backported_versions[i++] = "Sendmail 8.14.9/8.14.9/SuSE Linux 0.8";
real_versions[j++]       = "Sendmail 8.14.9/8.14.9/ConvertedOpenSUSE 42.1";

rx_backported_versions[k++] = 'PostgreSQL 9\\.3\\.10 .*\\(SUSE Linux\\) 4\\.8\\.5';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedOpenSUSE 42.1';

# https://web.archive.org/web/20110925201158/http://www.novell.com/products/linuxpackages/enterpriseserver/SP4/i386/index_all.html
# SuSE SLES9 SP4
backported_versions[i++]   = "Apache/1.3.29 (Linux/SUSE)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedSuSE)";

backported_versions[i++]   = "Apache/2.0.59 (Linux/SuSE)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedSuSE)";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.20";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Mac OS X 10.4 Server
backported_versions[i++]   = "Apache/1.3.33 (Darwin)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";

# Mac OS X 10.5 (Darwin becomes Unix) [2008-002 does *not* backport the fixes]
#backported_versions[i++]   = "Apache/2.2.6 (Unix) mod_ssl/2.2.6 OpenSSL/0.9.7l";
#real_versions[j++]         = "Apache/2.2.99";

# Mac OS X 10.5.2, with security update 2008-002
backported_versions[i++]   = "Apache/2.2.8 (Unix) mod_ssl/2.2.8 OpenSSL/0.9.7l";
real_versions[j++]         = "Apache/2.2.99";

# Apache Server on Mac OS X 10.6 (Client)

backported_versions[i++]   = "Apache/2.2.11 (Unix) mod_ssl/2.2.11 OpenSSL/0.9.8k DAV/2";
real_versions[j++]         = "Apache/2.2.99";

# Mac OS X Server - Admin
backported_versions[i++]   = "Apache/1.3.27 (Darwin) mod_ssl/2.8.12 OpenSSL/0.9.7b";
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin) mod_ssl/2.9.99 OpenSSL/0.9.99z";

# Mac OS X Server
backported_versions[i++]   = "Apache/1.3.27 (Darwin)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";

# Mac OS X Server - 10.6
backported_versions[i++]   = "Apache/2.2.11 (Unix)";
real_versions[j++]     = "Apache/2.2.99";

# - in 10.6.7
backported_versions[i++]   = "Apache/2.2.17 (Unix)";
real_versions[j++]     = "Apache/2.2.99";

# - with Security Update 2011-006
backported_versions[i++]   = "Apache/2.2.20 (Unix)";
real_versions[j++]     = "Apache/2.2.99";

# - with Security Update 2012-001
backported_versions[i++]   = "Apache/2.2.21 (Unix)";
real_versions[j++]     = "Apache/2.2.99";

# - with Security Update 2012-004
backported_versions[i++]   = "Apache/2.2.22 (Unix)";
real_versions[j++]     = "Apache/2.2.99";

# Mac OS X Server - 10.7
backported_versions[i++]   = "Apache/2.2.21 (Unix) mod_ssl/2.2.21 OpenSSL/0.9.8r DAV/2";
real_versions[j++]     = "Apache/2.2.99";

# Mac OS X 10.8
backported_versions[i++]   = "OpenSSH_5.9";
real_versions[j++]     = "OpenSSH_9.99";

backported_versions[i++]   = "Apache/2.2.22 (Unix) DAV/2 mod_ssl/2.2.22 OpenSSL/0.9.8r";
real_versions[j++]         = "Apache/2.2.99";

# MAc OS X 10.8 Server
backported_versions[i++]   = "Apache/2.2.22 (Unix) DAV/2 mod_fastcgi/2.4.6 mod_ssl/2.2.22 OpenSSL/0.9.8r";
real_versions[j++]         = "Apache/2.2.99";

# Mac OS X 10.9 (also in Fedora 19)
backported_versions[i++]   = "OpenSSH_6.2";
real_versions[j++]         = "OpenSSH_9.9.99";

# Mac OS X 10.9 Server
backported_versions[i++]   = "Apache/2.2.24 (Unix) DAV/2 mod_ssl/2.2.24 OpenSSL/0.9.8y";
real_versions[j++]         = "Apache/2.2.99";

# Mac OS X 10.9 Server + Security Update 2014-002
backported_versions[i++]   = "Apache/2.2.26 (Unix) DAV/2 mod_ssl/2.2.26 OpenSSL/0.9.8y";
real_versions[j++]         = "Apache/2.2.99";

# Fedora FC1
backported_versions[i++]   = "Apache/2.0.50 (Fedora)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedFedora)";

# Fedora FC2
backported_versions[i++]   = "Apache/2.0.51 (Fedora)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedFedora)";

backported_versions[i++]   = "<title>Apache Tomcat/4.1.27";
real_versions[j++]         = "<title>Apache Tomcat/4.1.99";

# Fedora FC3
backported_versions[i++]   = "Apache/2.0.52 (Fedora)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedFedora)";

# Fedora FC4
backported_versions[i++]   = "Apache/2.0.54 (Fedora)";
real_versions[j++]         = "Apache/2.999.999 (ConvertedFedora)";

backported_versions[i++]   = "<title>Apache Tomcat/5.0.30";
real_versions[j++]         = "<title>Apache Tomcat/5.0.99";

# Fedora FC5
backported_versions[i++]   = "Apache/2.2.0 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.15";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC6
backported_versions[i++]   = "Apache/2.2.3 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_4.3p2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.17";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC7
backported_versions[i++]   = "Apache/2.2.4 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.8 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_4.5p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.23";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC8
backported_versions[i++]   = "Apache/2.2.6 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_4.7p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.23";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC9
backported_versions[i++]   = "Apache/2.2.9 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.0p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.26";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC10
backported_versions[i++]   = "Apache/2.2.11 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.1p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Fedora FC11
backported_versions[i++]   = "Apache/2.2.11 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.2p1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.18";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Fedora 12

backported_versions[i++]   = "Apache/2.2.15 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.26";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Fedora 13
backported_versions[i++]   = "Apache/2.2.16 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.17 (Fedora)";      # patched
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.4";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.26";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Fedora 14
backported_versions[i++]   = "Apache/2.2.16 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.17 (Fedora)";      # patched
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.5";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.26";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Fedora 15
backported_versions[i++]   = "Apache/2.2.17 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.19 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.21 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.22 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.6";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.31";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.30";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Fedora 16
backported_versions[i++]   = "Apache/2.2.21 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.22 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.8";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.31";
real_versions[j++]         = "<title>Apache Tomcat 5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.32";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.22";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.6 .*\\(Red Hat 4\\.6\\.3-2\\)';
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 17
backported_versions[i++]   = "Apache/2.2.22 (Fedora)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.2.23 (Fedora)";     # patched
real_versions[j++]         = "Apache/2.2.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_5.9";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.32";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.27";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.1\\.6 .*\\(Red Hat 4\\.7\\.2-2\\)';
rx_real_versions[l++]         = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 18

backported_versions[i++]   = "Apache/2.4.3 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.4 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.6 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_6.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.35";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.34";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.2\\.2 .*\\(Red Hat 4\\.7\\.2-8\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 19

backported_versions[i++]   = "Apache/2.4.4 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.6 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.7 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.9 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.10 (Fedora)";       # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "OpenSSH_6.2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.40";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.47"; # patched
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.2\\.4 .*\\(Red Hat 4\\.8\\.0-1\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.2\\.8 .*\\(Red Hat 4\\.8\\.2-7\\)'; # patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 20

backported_versions[i++]   = "Apache/2.4.6 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.10 (Fedora) PHP/5.5.26";           # patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.5.99";

backported_versions[i++]   = "OpenSSH_6.4";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.47";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.52";             # patched
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.3\\.2 .*\\(Red Hat 4\\.8\\.2\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.3\\.6 .*\\(Red Hat 4\\.8\\.3-7\\)'; # patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 21

backported_versions[i++]   = "Apache/2.4.10 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.10 (Fedora) PHP/5.6.8";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "Apache/2.4.16 (Fedora) PHP/5.6.11"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "OpenSSH_6.6.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.54";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.3\\.5 .*\\(Red Hat 4\\.9\\.1-11\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.3\\.9 .*\\(Red Hat 4\\.9\\.2-6\\)'; # patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 22

backported_versions[i++]   = "Apache/2.4.12 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.16 (Fedora)"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.18 (Fedora)"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.12 (Fedora) PHP/5.6.9";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "Apache/2.4.16 (Fedora) PHP/5.6.12"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

rx_backported_versions[k++]  = 'Apache/2\\.4\\.18 \\(Fedora\\) PHP/5\\.6\\.(19|2[0-2])';
rx_real_versions[l++]        = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "OpenSSH_6.8";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "OpenSSH_6.9"; # Patched
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.59";
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/7.0.68"; # Patched
real_versions[j++]         = "<title>Apache Tomcat/7.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.4\\.1 .*\\(Red Hat 4\\.9\\.2-5\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.4\\.4 .*\\(Red Hat 5\\.1\\.1-1\\)'; # Patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.4\\.7 .*\\(Red Hat 5\\.3\\.1-2\\)'; # Patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 23

backported_versions[i++]   = "Apache/2.4.17 (Fedora)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.17 (Fedora) PHP/5.6.14";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "Apache/2.4.18 (Fedora) PHP/5.6.19"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "Apache/2.4.23 (Fedora) PHP/5.6.29"; # Patched
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "OpenSSH_7.1";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "OpenSSH_7.2"; # Patched
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/8.0.26";
real_versions[j++]         = "<title>Apache Tomcat/8.0.99";

backported_versions[i++]   = "<title>Apache Tomcat/8.0.39"; # Patched
real_versions[j++]         = "<title>Apache Tomcat/8.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.4\\.5 .*\\(Red Hat 5\\.1\\.1-4\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

rx_backported_versions[k++]  = 'PostgreSQL 9\\.4\\.9 .*\\(Red Hat 5\\.3\\.1-6\\)'; # Patched
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 24
backported_versions[i++]   = "Apache/2.4.23 (Fedora)"; # Same as Fedora 25
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.23 (Fedora) PHP/5.6.23";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "Apache/2.4.25 (Fedora)"; # Same as Fedora 25
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.25 (Fedora) PHP/5.6.29";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/5.6.99";

backported_versions[i++]   = "OpenSSH_7.2";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/8.0.32";
real_versions[j++]         = "<title>Apache Tomcat/8.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.5\\.3 .*\\(Red Hat 6\\.0\\.0-0\\.20\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Fedora 25
#backported_versions[i++]   = "Apache/2.4.23 (Fedora)"; # Same as Fedora 25
#real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora)";

backported_versions[i++]   = "Apache/2.4.23 (Fedora) PHP/7.0.13";
real_versions[j++]         = "Apache/2.4.99 (ConvertedFedora) PHP/7.0.99";

backported_versions[i++]   = "OpenSSH_7.3";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/8.0.38";
real_versions[j++]         = "<title>Apache Tomcat/8.0.99";

rx_backported_versions[k++]  = 'PostgreSQL 9\\.5\\.5 .*\\(Red Hat 6\\.2\\.1-2\\)';
rx_real_versions[l++]        = 'PostgreSQL 9.99.99 ConvertedFedora';

# Mandriva 2008.0

backported_versions[i++]   = "Apache/2.2.6 (Mandriva Linux/PREFORK-8.2mdv2008.0)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-8.99mdv2008.0)";

backported_versions[i++]   = "OpenSSH_4.7";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.23";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

# Mandriva 2010.0

backported_versions[i++]   = "Apache/2.2.14 (Mandriva Linux/PREFORK-1.5mdv2010.0)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-1.99mdv2010.0)";

backported_versions[i++]   = "Apache/2.2.15 (Mandriva Linux/PREFORK-3.2mdv2010.2)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-3.99mdv2010.2)";

backported_versions[i++]   = "OpenSSH_5.3";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.27";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.20";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

# Mandriva 2010.2

backported_versions[i++]   = "OpenSSH_5.5";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/2.2.15 (Mandriva Linux/PREFORK-3.1mdv2010.1)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-3.99mdv2010.1)";

backported_versions[i++]   = "Apache/2.2.15 (Mandriva Linux/PREFORK-3.2mdv2010.2)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-3.99mdv2010.2)";

backported_versions[i++]   = "Apache/2.2.22 (Mandriva Linux/PREFORK-0.1mdv2010.2)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-0.99mdv2010.2)";

backported_versions[i++]   = "<title>Apache Tomcat/5.5.28";
real_versions[j++]         = "<title>Apache Tomcat/5.5.99";

backported_versions[i++]   = "<title>Apache Tomcat/6.0.26";
real_versions[j++]         = "<title>Apache Tomcat/6.0.99";

rx_backported_versions[k++]   = 'PostgreSQL 8\\.4\\.12 .*\\(GCC\\) 4\\.4\\.3[^0-9]';
rx_real_versions[l++]         = 'PostgreSQL 8.99.99 ConvertedMandriva Linux';

# Mandriva 2011.0

backported_versions[i++]   = "OpenSSH_5.8";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/2.2.22 (Mandriva Linux/PREFORK-0.1)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-0.1)";

backported_versions[i++]   = "Apache/2.2.24 (Mandriva Linux/PREFORK-0.1)";      # patched
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Linux/PREFORK-0.1)";

# Mandriva Business Server release 1

backported_versions[i++]   = "OpenSSH_5.9";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/2.2.23 (Mandriva/PREFORK-1.mbs1)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMandriva Business/PREFORK-1.mbs1)";

# Mageia 1

backported_versions[i++]   = "Apache/2.2.17 (Mageia/PREFORK-4.mga1)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMageia 1/PREFORK-4.mga1)";

backported_versions[i++]   = "OpenSSH_5.8";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "ProFTPD 1.3.3e ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

# Mageia 2

backported_versions[i++]   = "Apache/2.2.22 (Mageia/PREFORK-12.mga2)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedMageia 2/PREFORK-12.mga2)";

backported_versions[i++]   = "OpenSSH_5.9";
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "ProFTPD 1.3.3g ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

# Mageia 3

backported_versions[i++]   = "Apache/2.4.4 (Mageia)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedMageia 3)";

backported_versions[i++]   = "OpenSSH_6.1";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.4c ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

# Mageia 4

backported_versions[i++]   = "Apache/2.4.7 (Mageia)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedMageia 4)";

backported_versions[i++]   = "OpenSSH_6.2";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.4d ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

# Slackware 14.0

backported_versions[i++]   = "Apache/2.4.3 (Unix)";
real_versions[j++]         = "Apache/2.4.99 (Converted)";

backported_versions[i++]   = "OpenSSH_6.1";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.4a ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.5/8.14.5";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

backported_versions[i++]   = "vsFTPd 3.0.2";
real_versions[j++]         = "vsFTPd 9.9.9 (Converted)";

# Slackware 14.1

backported_versions[i++]   = "Apache/2.4.6 (Unix)";
real_versions[j++]         = "Apache/2.4.99 (Converted)";

backported_versions[i++]   = "OpenSSH_6.3";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "ProFTPD 1.3.4c ";
real_versions[j++]         = "ProFTPD 1.3.99 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

backported_versions[i++]   = "vsFTPd 3.0.2";
real_versions[j++]         = "vsFTPd 9.9.9 (Converted)";

# Debian - wu-ftpd
backported_versions[i++]   = "FTP Server (Version wu-2.6.2";
real_versions[j++]         = "FTP Server (Version wu-2.9.99";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.0\\.10 .*\\(GCC\\) 4\\.6\\.1 .*\\(Mandriva\\)';
rx_real_versions[l++]          = 'PostgreSQL 9.99.99 ConvertedMandriva Linux';

# EulerOS 2.0 SP1
backported_versions[i++]   = "vsFTPd 3.0.2";
real_versions[j++]         = "vsFTPd 9.9.9 (Converted)";

backported_versions[i++]   = "Apache/2.4.6 ()";
real_versions[j++]         = "Apache/2.4.99 (Converted)";

backported_versions[i++]   = "OpenSSH_6.6.1";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

rx_backported_versions[k++]   = 'PostgreSQL 9\\.2\\.18 .*\\(GCC\\) 4\\.8\\.3 .*\\(EulerOS\\)';
rx_real_versions[l++]          = 'PostgreSQL 9.99.99 ConvertedEulerOS';

backported_versions[i++] = "<title>Apache Tomcat/7.0.69";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

# Virtuozzo 7.2
# Virtuozzo 7.3
backported_versions[i++]   = "Apache/2.4.6 (VZP)";
real_versions[j++]         = "Apache/2.4.99 (ConvertedVirtuozzo)";

backported_versions[i++]   = "OpenSSH_6.6.1";
real_versions[j++]         = "OpenSSH_9.9.99 (Converted)";

backported_versions[i++]   = "vsFTPd 3.0.2";
real_versions[j++]         = "vsFTPd 9.9.9 (Converted)";

backported_versions[i++]   = "Sendmail 8.14.7/8.14.7";
real_versions[j++]         = "Sendmail 8.99.9/8.99.9 (Converted)";

rx_backported_versions[k++] = 'PostgreSQL 9\\.2\\.18 .*-virtuozzo-linux-gnu.*\\(GCC\\) 4\\.8\\.5 .*\\(Red Hat\\)';
rx_real_versions[l++]       = 'PostgreSQL 9.99.99 ConvertedVirtuozzo Linux';

backported_versions[i++] = "<title>Apache Tomcat/7.0.69";
real_versions[j++]       = "<title>Apache Tomcat/7.99.99";

if ( "Avoid false alarms" ><  paranoia && "Normal" >!< paranoia )
{
 # OpenBSD
 backported_versions[i++]   = "Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7j";
 real_versions[j++]         = "Apache/1.3.99 (OpenBSD) mod_ssl/2.9.99 OpenSSL/0.9.99z";
}

for ( i = 0 ; backported_versions[i] ; i ++ )
 {
 if ( tolower(backported_versions[i]) >< tolower(banner) )
  {
   str = ereg_replace(pattern:"([\\?.*(){}^$+])", replace:"\\1", string:backported_versions[i]);
   backported = 1;
   replace_kb_item(name:"general/backported", value:TRUE);
   return ereg_replace(pattern:str, replace:real_versions[i], string:banner, icase:TRUE);
  }
 }

 for ( i = 0; rx_backported_versions[i]; i ++ )
 {
  if ( egrep(pattern:rx_backported_versions[i], string:banner, icase:TRUE) )
   {
   backported = 1;
   replace_kb_item(name:"general/backported", value:TRUE);
   return ereg_replace(pattern:rx_backported_versions[i], replace:rx_real_versions[i], string:banner, icase:TRUE);
   }
 }


 return banner;
}

##
# Extracts the PHP version from a web server banner
#
# @param banner web server banner
#
# @return the PHP version extracted from 'banner',
#         NULL if a PHP version was not found in 'banner',
#         NULL if PHP appears to be backported and Report Paranoia is not set to 'Paranoid'
##
function get_php_version(banner)
{
 local_var www_version, php_version, paranoia;
 local_var xpowered_by;
 paranoia = get_kb_item("global_settings/report_paranoia");

 www_version = banner;
 if ( ! www_version ) return NULL;

 php_version = egrep(pattern:"Server:.*PHP/[0-9].", string:www_version);
 if ( ! php_version ) {
  php_version = egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:www_version);
  xpowered_by = 1;
  }
 if ( ! php_version ) return NULL;

 # backported
 if (
   "Paranoid" >!< paranoia &&
   (
     # by Debian
     ereg(string: php_version, pattern: "PHP/[0-9.]+-([0-9.]+[~+](woody|sarge|etch|lenny|squeeze)|Debian-)[0-9]") ||
     # by Dotdeb (Debian)
     ereg(string: php_version, pattern: "PHP/[0-9.]+-[0-9]+\.dotdeb\.[0-9]") ||
     # by Gentoo
     ereg(string: php_version, pattern: "PHP/[0-9.]+(RC[0-9]+)?(_pre[0-9]+)?(-pl[0-9]+)?-gentoo") ||
     # by Ubuntu
     ereg(string: php_version, pattern: "PHP/[0-9.]+-([0-9]+ubuntu|Debian-[0-9.]+~(hoary|breezy|dapper))[0-9]")
   )
 )
 {
   backported = 1;
   replace_kb_item(name:"general/backported", value:TRUE);
   return NULL;
 }

 php_version = ereg_replace(pattern:".*(PHP/[0-9.]*)[^0-9.].*", string:php_version, replace:"\1");
 if ( "Paranoid" >< paranoia ) return php_version;

 #
 # Is this a backported banner?
 #
 get_backport_banner(banner:banner);
 if ( backported ) return NULL;
 # Avoid a FP if Apache is configured as 'ProductOnly'
 if ( xpowered_by && egrep(pattern:"^Server: Apache.?$", string:www_version) )
  return NULL;

 return php_version;
}
