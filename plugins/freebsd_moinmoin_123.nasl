# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_1ecf4ca1f7ad11d896c900061bc2ad93.nasl.
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
 script_id(14385);
 script_version("$Revision: 1.19 $");
 script_bugtraq_id(10801);
 script_bugtraq_id(10805);

 script_name(english:"FreeBSD : moinmoin -- ACL group bypass (115)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: moinmoin');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=482
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=483
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=564
http://secunia.com/advisories/11832
http://security.gentoo.org/glsa/glsa-200408-25.xml
http://www.mozilla.org/security/announce/2007/mfsa2007-01.html
http://www.mozilla.org/security/announce/2007/mfsa2007-02.html
http://www.opera.com/support/search/view/861/
http://www.osvdb.org/8194
http://www.osvdb.org/8195');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/1ecf4ca1-f7ad-11d8-96c9-00061bc2ad93.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
 script_cvs_date("$Date: 2011/10/03 00:48:25 $");
 script_end_attributes();
 script_cve_id("CVE-2004-1462", "CVE-2004-1463");
 script_summary(english:"Check for moinmoin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #38135 (freebsd_pkg_1ecf4ca1f7ad11d896c900061bc2ad93.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"moinmoin<1.2.3");
