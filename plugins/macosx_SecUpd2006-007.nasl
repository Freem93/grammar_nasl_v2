#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(23740);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2006-4396", "CVE-2006-4398", "CVE-2006-4400", "CVE-2006-4401", "CVE-2006-4402",
               "CVE-2006-4403", "CVE-2006-4404", "CVE-2006-4406", "CVE-2006-4407", "CVE-2006-4408",
               "CVE-2006-4409", "CVE-2006-4410", "CVE-2006-4411", "CVE-2006-4412", "CVE-2006-5710");
 script_bugtraq_id(21335, 20862);
 script_osvdb_id(
  30180,
  30726,
  30727,
  30728,
  30729,
  30730,
  30731,
  30732,
  30733,
  30734,
  30735,
  30736,
  30737,
  30738,
  30739
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-007)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X which does not have
the security update 2006-007 applied.

Security Update 2006-007 contains several security fixes for the following 
programs :

 - AirPort
 - ATS
 - CFNetwork
 - Finder
 - Font Book
 - Font Importer
 - Installer
 - OpenSSL
 - PHP
 - PPP
 - Samba
 - Security Framework
 - VPN
 - WebKit
 - gnuzip
 - perl" );
 # http://web.archive.org/web/20061215055354/http://docs.info.apple.com/article.html?artnum=304829
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea04761" );
 script_set_attribute(attribute:"solution", value:
"Install the missing security update :

For Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate20060071048clientppc.html
http://www.apple.com/support/downloads/securityupdate20060071048clientintel.html
http://www.apple.com/support/downloads/securityupdate20060071048serverppc.html

For Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060071039client.html
http://www.apple.com/support/downloads/securityupdate20060071039server.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/28");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-8]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-007|2007-003)", string:packages) )
		 security_hole(0);
}
