#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18062);
 script_version ("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/04/21 16:08:18 $");

 script_cve_id(
   "CVE-2005-0969", 
   "CVE-2005-0970", 
   "CVE-2005-0971", 
   "CVE-2005-0972", 
   "CVE-2005-0973", 
   "CVE-2005-0974", 
   "CVE-2005-0975", 
   "CVE-2005-0976"
 );
 script_bugtraq_id(
   12295, 
   13202, 
   13203, 
   13207, 
   13221, 
   13222, 
   13223, 
   13225
 );
 script_osvdb_id(
   13102, 
   13103, 
   15637, 
   15638, 
   15639, 
   15640, 
   15641, 
   15642
 );

 script_name(english:"Mac OS X 10.3.x < 10.3.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3.x that is prior
to 10.3.9.

Mac OS X 10.3.9 contains several security fixes for :

  - Safari : a remote local zone script execution 
    vulnerability has been fixed
  - kernel : multiple local privilege escalation 
    vulnerabilities have been fixed" );
  # http://web.archive.org/web/20060419231453/http://docs.info.apple.com/article.html?artnum=301327
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0730bd0f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.3.9" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/04/12"); 
script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.3\.[0-8]([^0-9]|$)", string:os )) security_hole(0);
