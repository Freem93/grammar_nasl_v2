# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_7a9d5dfec50711d88898000d6111a684.nasl.
#
# Disabled on 2011/10/02.
#

#
# (C) Tenable Network Security, Inc.
#
# This script contains information extracted from VuXML :
#
# Copyright 2003-2006 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#   copyright notice, this list of conditions and the following
#   disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#   published online in any format, converted to PDF, PostScript,
#   RTF and other formats) must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#

include('compat.inc');

if ( description )
{
 script_id(12534);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0460");

 script_name(english:"FreeBSD : isc-dhcp3-server buffer overflow in logging mechanism (36)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: isc-dhcp3-');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.libgd.org/?do=details&amp;task_id=89
http://bugs.libgd.org/?do=details&amp;task_id=94
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=457
http://secunia.com/advisories/11608
http://www.ethereal.com/appnotes/enpa-sa-00014.html
http://www.frsirt.com/english/advisories/2007/2336
http://www.libgd.org/ReleaseNote020035
http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/mfsa2005-46.html
http://www.mozilla.org/security/announce/mfsa2005-47.html
http://www.osvdb.org/7237
http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-ldap_spaces
http://www.squirrelmail.org/security/issue/2005-01-14');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/7a9d5dfe-c507-11d8-8898-000d6111a684.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();
 script_summary(english:"Check for isc-dhcp3-");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36237 (freebsd_pkg_7a9d5dfec50711d88898000d6111a684.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"isc-dhcp3-{relay,server}>=3.0.1.r12<3.0.1.r14");
