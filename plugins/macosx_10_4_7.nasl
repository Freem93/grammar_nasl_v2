#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(21763);
 script_version ("$Revision: 1.21 $");
 script_cve_id(
   "CVE-2006-1468", 
   "CVE-2006-1469", 
   "CVE-2006-1470", 
   "CVE-2006-1471", 
   "CVE-2006-1989"
 );
 script_bugtraq_id(18686, 18724, 18728, 18731, 18733);
 script_osvdb_id(25120, 26930, 26931, 26932, 26933);

 script_name(english:"Mac OS X 10.4.x < 10.4.7 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4.x that is prior
to 10.4.7.

Mac OS X 10.4.7 contains several security fixes for the following 
programs :

 - AFP server
 - ImageIO
 - launched
 - OpenLDAP" );
 # http://web.archive.org/web/20070919094538/http://docs.info.apple.com/article.html?artnum=303973
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89e8bd42" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jun/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.7 :
http://www.apple.com/support/downloads/macosxupdate1047intel.html
http://www.apple.com/support/downloads/macosxupdate1047ppc.html
http://www.apple.com/support/downloads/macosxserverupdate1047.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/27");
 script_cvs_date("$Date: 2016/04/21 16:08:18 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-6]([^0-9]|$))", string:os)) security_hole(0);
