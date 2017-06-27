#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(28212);
 script_version ("$Revision: 1.22 $");
 if ( NASL_LEVEL >= 3000 )
  script_cve_id("CVE-2007-3456", "CVE-2007-4678", "CVE-2007-2926", "CVE-2005-0953", "CVE-2005-1260", 
                "CVE-2007-4679", "CVE-2007-4680", "CVE-2007-0464", "CVE-2007-4681", "CVE-2007-4682", 
                "CVE-2007-3999", "CVE-2007-4743", "CVE-2007-3749", "CVE-2007-4683", "CVE-2007-4684", 
                "CVE-2007-4685", "CVE-2006-6127", "CVE-2007-4686", "CVE-2007-4687", "CVE-2007-4688", 
                "CVE-2007-4269", "CVE-2007-4689", "CVE-2007-4267", "CVE-2007-4268", "CVE-2007-4690", 
                "CVE-2007-4691", "CVE-2007-0646", "CVE-2007-4692", "CVE-2007-4693", "CVE-2007-4694", 
                "CVE-2007-4695", "CVE-2007-4696", "CVE-2007-4697", "CVE-2007-4698", "CVE-2007-3758", 
                "CVE-2007-3760", "CVE-2007-4671", "CVE-2007-3756", "CVE-2007-4699", "CVE-2007-4700", 
                "CVE-2007-4701");
 script_bugtraq_id(26444);
 script_osvdb_id(
  15237,
  16767,
  30695,
  32704,
  32708,
  36235,
  37324,
  37332,
  38054,
  38529,
  38531,
  38533,
  38535,
  40661,
  40662,
  40663,
  40664,
  40665,
  40666,
  40667,
  40668,
  40669,
  40670,
  40671,
  40672,
  40673,
  40674,
  40675,
  40676,
  40677,
  40678,
  40679,
  40680,
  40681,
  40682,
  40683,
  40684,
  40685,
  40686,
  40687,
  40688
 );
 script_xref(name:"TRA", value:"TRA-2007-07");

 script_name(english:"Mac OS X < 10.4.11 Multiple Vulnerabilities (Security Update 2007-008)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older
than version 10.4.11 or a version of Mac OS X 10.3 which does not have
Security Update 2007-008 applied. 

This update contains several security fixes for the following programs :

 - Flash Player Plugin
 - AppleRAID
 - BIND
 - bzip2
 - CFFTP
 - CFNetwork
 - CoreFoundation
 - CoreText
 - Kerberos
 - Kernel
 - remote_cmds
 - Networking
 - NFS
 - NSURL
 - Safari
 - SecurityAgent
 - WebCore
 - WebKit" );
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-07");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307041" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 : Upgrade to Mac OS X 10.4.11 :

http://www.apple.com/support/downloads/macosx10411updateppc.html
http://www.apple.com/support/downloads/macosx10411updateintel.html

Mac OS X 10.3 : Apply Security Update 2007-008 :

http://www.apple.com/support/downloads/securityupdate20070081039client.html
http://www.apple.com/support/downloads/securityupdate20070081039server.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16, 20, 22, 79, 119, 134, 189, 200, 264, 287, 362, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/31");
 script_cvs_date("$Date: 2016/11/28 21:06:37 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/09/04");
script_set_attribute(attribute:"plugin_type", value:"combined");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	confidence = get_kb_item("Host/OS/Confidence");
	if ( confidence <= 90 ) exit(0);
	}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.([1-9]$|10))", string:os)) security_hole(0);
else if ( ereg(pattern:"Mac OS X 10\.3\.", string:os) )
{
 packages = get_kb_item("Host/MacOSX/packages");
 if ( ! packages ) exit(0);
 if (!egrep(pattern:"^SecUpd(Srvr)?2007-008", string:packages)) security_hole(0);
}
