#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12566);
 script_bugtraq_id(10643);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0602");
 name["english"] = "FreeBSD : SA-04:13.linux";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the FreeBSD kernel which 
contains a programming error in the way it handles some Linux system calls, 
which may be exploited by an attacker to gain super-user privileges on the
remote host, or to crash it." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/8ecaaca2-cc07-11d8-858d-000d610a3b12.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_cvs_date("$Date: 2010/10/06 01:47:50 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD kernel";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");

port = 0;

package = get_kb_item("Host/FreeBSD/release");

if ( egrep(pattern:"FreeBSD-4\.[0-8]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_24") < 0 )
 {
  security_note(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_11") < 0 )
 {
  security_note(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.10", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_2") < 0 )
 {
  security_note(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.[012]", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_9") < 0 )
 {
  security_note(port);
  exit(0);
 }
}

