#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12613);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_cve_id("CVE-2004-0370");
 name["english"] = "FreeBSD : SA-04:06.ipv6 : setsockopt()";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of FreeBSD 5.2 older than FreeBSD 5.2.1-p4

There is a programming error in the version of this kernel which may allow
a local attacker to read portions of the kernel memory or to cause a system
panic by misusing the setsockopt() system call on IPv6 sockets." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/2c6acefd-8194-11d8-9645-0020ed76ef5a.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD kernel";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");

port = 0;

package = get_kb_item("Host/FreeBSD/release");
if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_4") < 0 )
 {
  security_note(port);
  exit(0);
 }
}

