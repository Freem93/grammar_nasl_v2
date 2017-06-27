# @DEPRECATED@
#
# This script has been deprecated by freebsd_kdelibs_3233.nasl.
#
# Disabled on 2011/10/02.
#

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14758);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_cve_id("CVE-2004-0717", "CVE-2004-0718", "CVE-2004-0721");
 name["english"] = "FreeBSD Ports : Multiple Browsers Frame Injection";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the following package :

kdelibs < 3.2.3_3
kdebase < 3.2.3_1
7.50 <= linux-opera < 7.52
7.50 <= opera < 7.52
firefox < 0.9 
linux-mozilla < 1.7
linux-mozilla-devel < 1.7
mozilla-gtk1 < 1.7
mozilla < 1.7,2
netscape7 < 7.2

These packages contain a bug which may allow an attacker to perform a frame
injection. An attacker may exploit this flaw by setting up a rogue website
which would insert its own frames in the pages of an otherwise trusted
web site." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/641859e8-eca1-11d8-b913-000c41e2cdad.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/16");
 script_end_attributes();

 
 summary["english"] = "Check for the version of several packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #14268 (freebsd_kdelibs_3233.nasl) instead.");




include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");
if ( ! pkgs ) exit(0);

package = egrep(pattern:"^kdelibs-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"kdelibs-3.2.3_3") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
package = egrep(pattern:"^kdebase-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"kdebase-3.2.3_1") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
package = egrep(pattern:"^linux-opera-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"linux-opera-7.52") < 0 &&
     pkg_cmp(pkg:package, reference:"linux-opera-7.50") >= 0 ) 
	{
	security_hole(0);
	exit(0);
	}
package = egrep(pattern:"^opera-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"opera-7.52") < 0 &&
     pkg_cmp(pkg:package, reference:"opera-7.50") >= 0 ) 
	{
	security_hole(0);
	exit(0);
	}


package = egrep(pattern:"^firefox-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"firefox-0.9") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}

package = egrep(pattern:"^linux-mozilla-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"linux-mozilla-1.7") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}

package = egrep(pattern:"^linux-mozilla-devel-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"linux-mozilla-devel-1.7") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}

package = egrep(pattern:"^mozilla-gtk1-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"mozilla-gtk1-1.7") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
package = egrep(pattern:"^mozilla-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"mozilla-1.7,2") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
package = egrep(pattern:"^netscape7-[0-9]", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"netscape7-7.2") < 0 ) 
	{
	security_hole(0);
	exit(0);
	}
