#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15419);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(11321);
 script_cve_id("CVE-2004-0919");
 name["english"] = "FreeBSD : SA-04:15.syscons";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of FreeBSD which contains a flaw in the 
syscons console driver.

There are boundary errors in the CONS_SCRSHOT ioctls that may allow a local
attacker to read portions of the kernel memory, which may contain sensitive
information." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/67710833-1626-11d9-bc4a-000c41e2cdad.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/04");
 script_cvs_date("$Date: 2010/10/06 01:50:04 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD";
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

if ( ! package ) exit(0);


if ( egrep(pattern:"FreeBSD-5\.", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_11") < 0 )
 {
  security_warning(port);
  exit(0);
 }
}

