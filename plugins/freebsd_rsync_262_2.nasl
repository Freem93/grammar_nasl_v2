# @DEPRECATED@
# 
# This script has been deprecated by freebsd_pkg_73ea07069c5711d893660020ed76ef5a.nasl.
#
# Disabled on 2011/10/01.


#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14386);
 script_bugtraq_id(10938);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0792");
 name["english"] = "FreeBSD Ports : rsync < 2.6.2_2";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of rsync installed.

There is a flaw in this version of rsync which, due to an input validation
error, would allow a remote attacker to gain access to the remote system.

An attacker, exploiting this flaw, would need network access to the TCP port.  

Successful exploitation requires that the rsync daemon is *not* running chroot." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/73ea0706-9c57-11d8-9366-0020ed76ef5a.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
 script_cvs_date("$Date: 2011/10/02 01:18:57 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the rsync package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}


exit(0, "This plugin has been deprecated. Refer to plugin #38112 (freebsd_pkg_73ea07069c5711d893660020ed76ef5a.nasl) instead.");



include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = egrep(pattern:"^rsync-[0-2]", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"rsync-2.6.2_2") < 0 ) 
	security_warning(0);
