# @DEPRECATED@
#
# This script has been deprecated and is no longer used 
# after a revamping of the Slackware generator.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18703);
script_version("$Revision: 1.7 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005-2010 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update." );
 script_set_attribute(attribute:"description", value:
"New zlib packages are available to fix a security problem which may impact
programs that link with zlib.

Here's the information from the Slackware 8.0 ChangeLog:

----------------------------
Mon Mar 11 13:32:40 PST 2002
patches/packages/zlib.tgz:  Upgraded to zlib-1.1.4.  This fixes a security
  problem which may introduce vulnerabilities into any program that links with
  zlib.  Quoting the advisory on zlib.org:

   Depending upon how and where the zlib routines are called from the given
   program, the resulting vulnerability may have one or more of the following
   impacts: denial of service, information leakage, or execution of arbitrary
   code.

Sites are urged to upgrade the zlib package immediately.

The complete advisory may be found here:
   http://www.zlib.org/advisory-2002-03-11.txt
" );
 script_set_attribute(attribute:"solution", value:"Update the packages that are referenced in the security advisory");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
script_end_attributes();


script_summary("SSA zlib upgrade fixes vulnerability");
name["english"] = "SSA-18703 zlib upgrade fixes vulnerability";
script_name(english:name["english"]);exit(0);
}

exit(0);

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "-current", pkgname: "zlib", pkgver: "1.1.4", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package zlib is vulnerable in Slackware -current
Upgrade to zlib-1.1.4-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
