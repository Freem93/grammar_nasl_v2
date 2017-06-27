#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(20113);
 script_version ("$Revision: 1.15 $");
 script_cve_id(
   "CVE-2005-1126", 
   "CVE-2005-1406", 
   "CVE-2005-2739", 
   "CVE-2005-2749",
   "CVE-2005-2750", 
   "CVE-2005-2751", 
   "CVE-2005-2752"
 );
 script_bugtraq_id(15252);
 script_osvdb_id(15514, 16091, 20427, 20428, 20429, 20430, 20431);

 script_name(english:"Mac OS X 10.4.x < 10.4.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes security
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4.x that is prior
to 10.4.3.

Mac OS X 10.4.3 contains several security fixes for :

- Finder
- Software Update
- memberd
- KeyChain
- Kernel" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.3 :
http://www.apple.com/support/downloads/macosxupdate1043.html
http://www.apple.com/support/downloads/macosxserver1043.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200, 399);
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/Oct/msg00000.html" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/10/31");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
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

if ( ereg(pattern:"Mac OS X 10\.4($|\.[12]([^0-9]|$))", string:os )) security_note(0);
