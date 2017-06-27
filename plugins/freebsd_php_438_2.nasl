# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_ad74a1bd16d211d9bc4a000c41e2cdad.nasl.
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
 script_id(15493);
 script_version("$Revision: 1.6 $");

 script_name(english:"FreeBSD : php -- php_variables memory disclosure (145)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: mod_php4-twig');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://drupal.org/node/184315
http://drupal.org/node/184316
http://drupal.org/node/184320
http://drupal.org/node/184348
http://drupal.org/node/184354
http://gaim.sourceforge.net/security/?id=6
http://scary.beasts.org/security/CESA-2004-002.txt
http://secunia.com/advisories/27292
http://www.cipher.org.uk/index.php?p=advisories/Certificate_Spoofing_Mozilla_FireFox_25-07-2004.advisory
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.opera.com/support/search/view/881/');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/18");
 script_end_attributes();
 script_summary(english:"Check for mod_php4-twig");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36848 (freebsd_pkg_ad74a1bd16d211d9bc4a000c41e2cdad.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"mod_php4-twig<=4.3.8_2");

pkg_test(pkg:"php4-cgi<=4.3.8_2");

pkg_test(pkg:"php4-cli<=4.3.8_2");

pkg_test(pkg:"php4-dtc<=4.3.8_2");

pkg_test(pkg:"php4-horde<=4.3.8_2");

pkg_test(pkg:"php4-nms<=4.3.8_2");

pkg_test(pkg:"php4<=4.3.8_2");

pkg_test(pkg:"mod_php>=4<=4.3.8_2,1");

pkg_test(pkg:"mod_php4>=4<=4.3.8_2,1");

pkg_test(pkg:"php5<=5.0.1");

pkg_test(pkg:"php5-cgi<=5.0.1");

pkg_test(pkg:"php5-cli<=5.0.1");

pkg_test(pkg:"mod_php5<=5.0.1,1");
