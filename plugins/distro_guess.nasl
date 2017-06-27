#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18261);
  script_version("$Revision: 1.99 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"Apache Banner Linux Distribution Disclosure");
  script_summary(english:"Guesses the remote distribution version.");

  script_set_attribute(attribute:"synopsis", value:
"The name of the Linux distribution running on the remote host was
found in the banner of the web server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to extract the banner of the Apache web server and
determine which Linux distribution the remote host is running.");
  script_set_attribute(attribute:"solution", value:
"If you do not wish to display this information, edit 'httpd.conf' and
set the directive 'ServerTokens Prod' and restart Apache.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#-----------------------------------------------------------#
# Mandrake                                                  #
#-----------------------------------------------------------#

i = 0; j = 0;
sig[i++]	= "Apache/1.3.6 (Unix) (Mandrake/Linux)";
name[j++]	= "Mandrake Linux 6.0";

sig[i++]	= "Apache/1.3.9 (Unix) (NetRevolution Advanced Server/Linux-Mandrake)";
name[j++]	= "Mandrake Linux 6.1";

sig[i++]	= "Apache/1.3.9 (Unix) (NetRevolution Advanced Server/Linux-Mandrake)";
name[j++]	= "Mandrake Linux 7.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.12 (NetRevolution/Linux-Mandrake)";
name[j++]	= "Mandrake Linux 7.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.14 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 7.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.19 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 8.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.20 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.22 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 7.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.22 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 7.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.22 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.22 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.27 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.44 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.47 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.2";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.47 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.29 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.31 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 10.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.50 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0"; # patched

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.50 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.53 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2005";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.54 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2006";

sig[i++]	= "Apache-AdvancedExtranetServer/2.2.3 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2007";

sig[i++]	= "Apache-AdvancedExtranetServer/2.2.4 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2007.1";

sig[i++]	= "Apache/2.2.6 (Mandriva Linux/PREFORK-8.2mdv2008.0)";
name[j++]	= "Mandriva Linux 2008.0";

sig[i++]	= "Apache/2.2.9 (Mandriva Linux/PREFORK-12.9mdv2009.0)";
name[j++]	= "Mandriva Linux 2009.0";

sig[i++]	= "Apache/2.2.14 (Mandriva Linux/PREFORK-1.5mdv2010.0)";
name[j++]	= "Mandriva Linux 2010.0";

sig[i++]	= "Apache/2.2.15 (Mandriva Linux/PREFORK-3.1mdv2010.1)";
name[j++]	= "Mandriva Linux 2010.1";

sig[i++]	= "Apache/2.2.15 (Mandriva Linux/PREFORK-3.1mdv2010.1)";
name[j++]	= "Mandriva Linux 2010.2";

sig[i++]        = "Apache/2.2.15 (Mandriva Linux/PREFORK-3.2mdv2010.2)";
name[j++]       = "Mandriva Linux 2010.2";

sig[i++]        = "Apache/2.2.22 (Mandriva Linux/PREFORK-0.1mdv2010.2)";
name[j++]       = "Mandriva Linux 2010.2";

sig[i++]        = "Apache/2.2.22 (Mandriva Linux/PREFORK-0.1)";
name[j++]       = "Mandriva Linux 2011.0";

sig[i++]        = "Apache/2.2.24 (Mandriva Linux/PREFORK-0.1)";   # patched
name[j++]       = "Mandriva Linux 2011.0";

sig[i++]        = "Apache/2.2.23 (Mandriva/PREFORK-1.mbs1)";
name[j++]       = "Mandriva Business Server 1";

#-----------------------------------------------------------#
# Mageia                                                    #
#-----------------------------------------------------------#

sig[i++]        = "Apache/2.2.17 (Mageia/PREFORK-4.mga1)";
name[j++]       = "Mageia 1";

sig[i++]        = "Apache/2.2.22 (Mageia/PREFORK-12.mga2)";
name[j++]       = "Mageia 2";

sig[i++]        = "Apache/2.4.4 (Mageia)";
name[j++]       = "Mageia 3";

sig[i++]        = "Apache/2.4.7 (Mageia)";
name[j++]       = "Mageia 4";

#-----------------------------------------------------------#
# Red Hat                                                   #
#-----------------------------------------------------------#

sig[i++] 	= "Apache/1.2.6 Red Hat";
name[j++]	= "Red Hat Linux 5.1";

sig[i++] 	= "Apache/1.3.3 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 5.2";

sig[i++] 	= "Apache/1.3.6 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.0";

sig[i++] 	= "Apache/1.3.9 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.1";

sig[i++] 	= "Apache/1.3.12 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.2";

sig[i++] 	= "Apache/1.3.12 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 7.0";

sig[i++] 	= "Apache/1.3.19 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.1";

sig[i++] 	= "Apache/1.3.20 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.2";

sig[i++] 	= "Apache/1.3.23 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.3";

sig[i++]	= "Apache/2.0.40 (Red Hat Linux)";
name[j++]	= "Red Hat Linux 8.0";

sig[i++]	= "Apache/2.0.40 (Red Hat Linux)";
name[j++]	= "Red Hat Linux 9";

sig[i++] 	= "Apache/1.3.22 (Unix)  (Red-Hat/Linux)";
name[j++]	= "Red Hat Enterprise Linux 2.1";

sig[i++]  	= "Apache/1.3.27 (Unix)  (Red-Hat/Linux)";
name[j++] 	= "Red Hat Enterprise Linux 2.1";

sig[i++]  	= "Apache/2.0.46 (Red Hat)";
name[j++] 	= "Red Hat Enterprise Linux 3";

sig[i++]  	= "Apache/2.0.46 (CentOS)";
name[j++] 	= "CentOS 3";

sig[i++]  	= "Apache/2.0.52 (Red Hat)";
name[j++] 	= "Red Hat Enterprise Linux 4";

sig[i++]  	= "Apache/2.0.52 (CentOS)";
name[j++] 	= "CentOS 4";

sig[i++]  	= "Apache/2.2.3 (Red Hat)";
name[j++] 	= "Red Hat Enterprise Linux 5";

sig[i++]  	= "Apache/2.2.3 (CentOS)";
name[j++] 	= "CentOS 5";

sig[i++]        = "Apache/2.2.15 (CentOS)";
name[j++]       = "CentOS 6";

sig[i++]        = "Apache/2.4.6 (CentOS)";
name[j++]       = "CentOS 7";

sig[i++]        = "Apache/2.2.15 (Red Hat)";
name[j++]       = "Red Hat Enterprise Linux 6";

sig[i++]  	= "Apache/2.0.52 (Oracle)";
name[j++] 	= "Oracle Unbreakable Linux 4";

sig[i++]  	= "Apache/2.2.3 (Oracle)";
name[j++] 	= "Oracle Enterprise Linux 5";

sig[i++]  	= "Apache/2.2.15 (Oracle)";
name[j++] 	= "Oracle Linux 6";

sig[i++]    = "Apache/2.4.6 (Red Hat)";
name[j++]   = "Oracle Linux 7";

sig[i++]  	= "Apache/2.0.46 (Scientific Linux)";
name[j++] 	= "Scientific Linux 3";

sig[i++]  	= "Apache/2.0.52 (Scientific Linux)";
name[j++] 	= "Scientific Linux 4";

sig[i++]  	= "Apache/2.2.3 (Scientific Linux)";
name[j++] 	= "Scientific Linux 5";

sig[i++]  	= "Apache/2.2.15 (Scientific Linux)";
name[j++] 	= "Scientific Linux 6";

sig[i++]  	= "Apache/2.4.6 (Scientific Linux)";
name[j++] 	= "Scientific Linux 7";

sig[i++]        = "Apache/2.4.6 (Red Hat)";
name[j++]       = "Red Hat Enterprise Linux 7";

sig[i++]  = "Apache/2.4.6 (Red Hat Enterprise Linux)";
name[j++] = "Red Hat Enterprise Linux 7";

#-----------------------------------------------------------#
# SuSE / openSUSE                                           #
#-----------------------------------------------------------#

sig[i++]	= "Apache/1.3.6 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.1";

sig[i++]	= "Apache/1.3.9 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.2";

sig[i++]	= "Apache/1.3.12 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.4";

sig[i++]	= "Apache/1.3.12 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 7.0";

sig[i++]	= "Apache/1.3.17 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 7.1";

sig[i++]	= "Apache/1.3.19 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 7.2";

sig[i++]	= "Apache/1.3.20 (Linux/SuSE)";
name[j++]	= "SuSE Linux 7.3";

sig[i++]	= "Apache/1.3.23 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.0";

sig[i++]	= "Apache/1.3.26 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1";

sig[i++]	= "Apache/1.3.27 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.2";

sig[i++]	= "Apache/1.3.28 (Linux/SUSE)";
name[j++]	= "SuSE Linux 9.0";

sig[i++]	= "Apache/2.0.40 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1";

sig[i++]	= "Apache/2.0.44 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.2";

sig[i++]	= "Apache/2.0.47 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.0";

sig[i++] 	= "Apache/2.0.48 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1";

sig[i++] 	= "Apache/2.0.48 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.2";

sig[i++] 	= "Apache/2.0.48 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.0";

sig[i++] 	= "Apache/2.0.49 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.1";

sig[i++] 	= "Apache/2.0.50 (Linux/SUSE)";
name[j++]	= "SuSE Linux 9.2";

sig[i++] 	= "Apache/2.0.53 (Linux/SUSE)";
name[j++]	= "SuSE Linux 9.3";

sig[i++] 	= "Apache/2.0.59 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.4";

sig[i++] 	= "Apache/2.0.54 (Linux/SUSE)";
name[j++]	= "SuSE Linux 10.0";

sig[i++] 	= "Apache/2.2.0 (Linux/SUSE)";
name[j++]	= "SuSE Linux 10.1";

sig[i++] 	= "Apache/2.2.3 (Linux/SUSE)";
name[j++]	= "SuSE Linux 10.2";

sig[i++] 	= "Apache/2.2.3 (Linux/SUSE)";
name[j++]	= "SLES10";

sig[i++] 	= "Apache/2.2.4 (Linux/SUSE)";
name[j++]	= "SuSE Linux 10.3";

sig[i++]        = "Apache/2.2.3 (Linux/SUSE)";
name[j++]       = "SuSE Linux 10.4";

sig[i++] 	= "Apache/2.2.10 (Linux/SUSE)";
name[j++]	= "SuSE Linux 11.0";

sig[i++] 	= "Apache/2.2.10 (Linux/SUSE)";
name[j++]	= "SuSE Linux 11.1";

sig[i++] 	= "Apache/2.2.12 (Linux/SUSE)";
name[j++]	= "SuSE Linux 11.1";

sig[i++]        = "Apache/2.2.12 (Linux/SUSE)";
name[j++]       = "SuSE Linux 11.3";

sig[i++]        = "Apache/2.4.10 (Linux/SUSE)";
name[j++]       = "SuSE Linux 12.0";

sig[i++]        = "Apache/2.2.17 (Linux/SUSE)";
name[j++]       = "openSUSE Linux 11.4";

sig[i++]        = "Apache/2.2.21 (Linux/SUSE)";
name[j++]       = "openSUSE Linux 12.1";

sig[i++]        = "Apache/2.2.22 (Linux/SUSE)";
name[j++]       = "openSUSE Linux 12.2";

sig[i++]        = "Apache/2.2.22 (Linux/SUSE)";
name[j++]       = "openSUSE Linux 12.3";

sig[i++]        = "Apache/2.4.16 (Linux/SUSE)";
name[j++]       = "openSUSE Linux 42.1";

#-----------------------------------------------------------#
# Fedora                                                    #
#-----------------------------------------------------------#

sig[i++] 	= "Apache/2.0.47 (Fedora)";
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.48 (Fedora)"; # patched
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.49 (Fedora)";
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.50 (Fedora)";
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.49 (Fedora)";
name[j++]	= "Fedora Core 2";

sig[i++] 	= "Apache/2.0.50 (Fedora)";
name[j++]	= "Fedora Core 2";

sig[i++] 	= "Apache/2.0.51 (Fedora)";
name[j++]	= "Fedora Core 2";

sig[i++] 	= "Apache/2.0.52 (Fedora)";
name[j++]	= "Fedora Core 3";

sig[i++] 	= "Apache/2.0.54 (Fedora)";
name[j++]	= "Fedora Core 4";

sig[i++] 	= "Apache/2.2.0 (Fedora)";
name[j++]	= "Fedora Core 5";

sig[i++] 	= "Apache/2.2.3 (Fedora)";
name[j++]	= "Fedora Core 6";

sig[i++] 	= "Apache/2.2.4 (Fedora)";
name[j++]	= "Fedora 7";

sig[i++] 	= "Apache/2.2.8 (Fedora)";   # patched
name[j++]	= "Fedora 7";

sig[i++] 	= "Apache/2.2.6 (Fedora)";
name[j++]	= "Fedora 8";

sig[i++] 	= "Apache/2.2.9 (Fedora)";
name[j++]	= "Fedora 9";

sig[i++]        = "Apache/2.2.11 (Fedora)";
name[j++]       = "Fedora 10";

sig[i++]        = "Apache/2.2.11 (Fedora)";
name[j++]       = "Fedora 11";

sig[i++]        = "Apache/2.2.14 (Fedora)";
name[j++]       = "Fedora 12";

sig[i++]        = "Apache/2.2.15 (Fedora)";  # patched
name[j++]       = "Fedora 12";

sig[i++]        = "Apache/2.2.15 (Fedora)";
name[j++]       = "Fedora 13";

sig[i++]        = "Apache/2.2.16 (Fedora)";  # patched
name[j++]       = "Fedora 13";

sig[i++]        = "Apache/2.2.17 (Fedora)";  # patched
name[j++]       = "Fedora 13";

sig[i++]        = "Apache/2.2.16 (Fedora)";
name[j++]       = "Fedora 14";

sig[i++]        = "Apache/2.2.17 (Fedora)";  # patched
name[j++]       = "Fedora 14";

sig[i++]        = "Apache/2.2.17 (Fedora)";
name[j++]       = "Fedora 15";

sig[i++]        = "Apache/2.2.19 (Fedora)";  # patched
name[j++]       = "Fedora 15";

sig[i++]        = "Apache/2.2.21 (Fedora)";  # patched
name[j++]       = "Fedora 15";

sig[i++]        = "Apache/2.2.22 (Fedora)";  # patched
name[j++]       = "Fedora 15";

sig[i++]        = "Apache/2.2.21 (Fedora)";
name[j++]       = "Fedora 16";

sig[i++]        = "Apache/2.2.22 (Fedora)";  # patched
name[j++]       = "Fedora 16";

sig[i++]        = "Apache/2.2.22 (Fedora)";
name[j++]       = "Fedora 17";

sig[i++]        = "Apache/2.2.23 (Fedora)";  # patched
name[j++]       = "Fedora 17";

sig[i++]        = "Apache/2.4.3 (Fedora)";
name[j++]       = "Fedora 18";

sig[i++]        = "Apache/2.4.4 (Fedora)";  # patched
name[j++]       = "Fedora 18";

sig[i++]        = "Apache/2.4.6 (Fedora)";  # patched
name[j++]       = "Fedora 18";

sig[i++]        = "Apache/2.4.4 (Fedora)";
name[j++]       = "Fedora 19";

sig[i++]        = "Apache/2.4.6 (Fedora)";  # patched
name[j++]       = "Fedora 19";

sig[i++]        = "Apache/2.4.7 (Fedora)";  # patched
name[j++]       = "Fedora 19";

sig[i++]        = "Apache/2.4.6 (Fedora)";
name[j++]       = "Fedora 20";

sig[i++]        = "Apache/2.4.10 (Fedora)";
name[j++]       = "Fedora 21";

sig[i++]        = "Apache/2.4.16 (Fedora)";
name[j++]       = "Fedora 21";

sig[i++]        = "Apache/2.4.12 (Fedora)";
name[j++]       = "Fedora 22";

sig[i++]        = "Apache/2.4.18 (Fedora)"; # patched
name[j++]       = "Fedora 22";

sig[i++]        = "Apache/2.4.17 (Fedora)";
name[j++]       = "Fedora 23";

sig[i++]        = "Apache/2.4.23 (Fedora)"; # patched
name[j++]       = "Fedora 23";

sig[i++]        = "Apache/2.4.23 (Fedora)";
name[j++]       = "Fedora 24";

sig[i++]        = "Apache/2.4.23 (Fedora)";
name[j++]       = "Fedora 25";

#-----------------------------------------------------------#
# Debian                                                    #
#-----------------------------------------------------------#

sig[i++]	= "Apache/1.0.5 (Unix) Debian/GNU";
name[j++]	= "Debian 1.1 (buzz)";

sig[i++]	= "Apache/1.1.1 (Unix) Debian/GNU";
name[j++]	= "Debian 1.2 (rex)";

sig[i++]	= "Apache/1.1.3 (Unix) Debian/GNU";
name[j++]	= "Debian 1.3 (bo)";

sig[i++]	= "Apache/1.3.0 (Unix) Debian/GNU";
name[j++]	= "Debian 2.0 (hamm)";

sig[i++]	= "Apache/1.3.3 (Unix) Debian/GNU";
name[j++]	= "Debian 2.1 (slink)";
# And also Corel Linux

sig[i++]	= "Apache/1.3.9 (Unix) Debian/GNU";
name[j++]	= "Debian 2.2 (potato)";

sig[i++]	= "Apache/1.3.26 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.0 (woody)";

sig[i++]	= "Apache/1.3.33 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.1 (sarge)";

sig[i++]	= "Apache/1.3.34 (Debian)";
name[j++]	= "Debian 4.0 (etch)";

sig[i++]	= "Apache/2.0.54 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.1 (sarge)";

sig[i++]	= "Apache/2.2.3 (Debian)";
name[j++]	= "Debian 4.0 (etch)";

sig[i++]        = "Apache/2.2.9 (Debian)";
name[j++]       = "Debian 5.0 (lenny)";

sig[i++]        = "Apache/2.2.16 (Debian)";
name[j++]       = "Debian 6.0 (squeeze)";

sig[i++]        = "Apache/2.2.22 (Debian)";
name[j++]       = "Debian 7.0 (wheezy)";

sig[i++]  = "Apache/2.4.10 (Debian)";
name[j++] = "Debian 8.0 (jessie)";

sig[i++]	= "Apache/1.3.33 (Unix) Debian GNU/Linux";
name[j++]	= "Debian unstable (sid)";

sig[i++]	= "Apache/2.0.55 (Unix) Debian GNU/Linux";
name[j++]	= "Debian unstable (sid)";

sig[i++]	= "Apache/2.2.22 (Debian)";
name[j++]	= "Debian unstable (sid)";

sig[i++]	= "Apache/2.2.22 (Debian)";
name[j++]	= "Debian testing (wheezy)";

#-----------------------------------------------------------#
# Ubuntu						    #
#-----------------------------------------------------------#

sig[i++]	= "Apache/2.0.50 (Ubuntu)";
name[j++]	= "Ubuntu 4.10 (warty)";

sig[i++]	= "Apache/2.0.53 (Ubuntu)";
name[j++]	= "Ubuntu 5.04 (hoary)";

sig[i++]	= "Apache/2.0.54 (Ubuntu)";
name[j++]	= "Ubuntu 5.10 (breezy)";

sig[i++]	= "Apache/2.0.55 (Ubuntu)";
name[j++]	= "Ubuntu 6.06 (dapper)";

sig[i++]	= "Apache/2.0.55 (Ubuntu)";
name[j++]	= "Ubuntu 6.10 (edgy)";

sig[i++]	= "Apache/2.2.3 (Ubuntu)";
name[j++]	= "Ubuntu 7.10 (feisty)";

sig[i++]        = "Apache/2.2.8 (Ubuntu)";
name[j++]       = "Ubuntu 8.04 (gutsy)";

sig[i++]        = "Apache/2.2.9 (Ubuntu)";
name[j++]       = "Ubuntu 8.10 (intrepid)";

sig[i++]        = "Apache/2.2.11 (Ubuntu)";
name[j++]       = "Ubuntu 9.04 (jaunty)";

sig[i++]        = "Apache/2.2.12 (Ubuntu)";
name[j++]       = "Ubuntu 9.10 (karmic)";

sig[i++]        = "Apache/2.2.14 (Ubuntu)";
name[j++]       = "Ubuntu 10.04 (lucid)";

sig[i++]        = "Apache/2.2.16 (Ubuntu)";
name[j++]       = "Ubuntu 10.10 (maverick)";

sig[i++]        = "Apache/2.2.17 (Ubuntu)";
name[j++]       = "Ubuntu 11.04 (natty)";

sig[i++]        = "Apache/2.2.20 (Ubuntu)";
name[j++]       = "Ubuntu 11.10 (oneiric)";

sig[i++]        = "Apache/2.2.22 (Ubuntu)";
name[j++]       = "Ubuntu 12.04 (precise)";

sig[i++]        = "Apache/2.2.22 (Ubuntu)";
name[j++]       = "Ubuntu 12.10 (quantal)";

sig[i++]        = "Apache/2.2.22 (Ubuntu)";
name[j++]       = "Ubuntu 13.04 (raring)";

sig[i++]        = "Apache/2.4.6 (Ubuntu)";
name[j++]       = "Ubuntu 13.10 (saucy)";

sig[i++]        = "Apache/2.4.7 (Ubuntu)";
name[j++]       = "Ubuntu 14.04 (trusty)";

sig[i++]        = "Apache/2.4.10 (Ubuntu)";
name[j++]       = "Ubuntu 14.10 (utopic)";

sig[i++]        = "Apache/2.4.10 (Ubuntu)";
name[j++]       = "Ubuntu 15.04 (vivid)";

sig[i++]        = "Apache/2.4.12 (Ubuntu)";
name[j++]       = "Ubuntu 15.10 (wily)";

sig[i++]        = "Apache/2.4.18 (Ubuntu)";
name[j++]       = "Ubuntu 16.04 (xenial)";

sig[i++]        = "Apache/2.4.18 (Ubuntu)";
name[j++]       = "Ubuntu 16.10 (yakkety)";

#-----------------------------------------------------------#
# Trustix                                                   #
#-----------------------------------------------------------#

sig[i++]  = "Apache/2.0.52 (Trustix Secure Linux/Linux)";
name[j++] = "Trustix 2.2 (Sunchild)";

#-----------------------------------------------------------#
# Virtuozzo                                                 #
#-----------------------------------------------------------#
sig[i++]  = "Apache/2.4.6 (VZP)";
name[j++] = "Virtuozzo 7.2";

sig[i++]  = "Apache/2.4.6 (VZP)";
name[j++] = "Virtuozzo 7.3";

#-----------------------------------------------------------#
# Begin code                                                #
#-----------------------------------------------------------#
ports = get_kb_list("Services/www");
if ( isnull(ports) ) ports = make_list(80);
else ports = make_list(ports);

foreach port ( ports )
{
 banner = get_http_banner(port:port, broken:TRUE);
 if ( banner )
 {
 match = NULL;
 num_matches = 0;

 # nb: the value of 'match' is used in os_fingerprint_http.nasl;
 #     if it's changed, it needs to be changed in that as well.
 for ( i = 0 ; sig[i] ; i ++ )
 {
   if ( sig[i] >< banner )
 	{
 	 if ( num_matches > 0 ) match += '\n';
	 match += ' - ' + name[i];
	 num_matches ++;
	}
 }

  if ( num_matches > 0  )
  {
    report = '\nThe Linux distribution detected was : \n' + match + '\n';
    security_note(port:0, extra:report);

    set_kb_item(name:"Host/Linux/Distribution", value:match);

    exit(0);
  }
 }

}
