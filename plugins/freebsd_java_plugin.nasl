# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_ac619d063ef811d98741c942c075aa41.nasl.
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
 script_id(15866);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-1029");

 script_name(english:"FreeBSD : jdk/jre -- Security Vulnerability With Java Plugin (81)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: diablo-jdk');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(264);
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://drupal.org/node/184315
http://drupal.org/node/184316
http://drupal.org/node/184320
http://drupal.org/node/184348
http://drupal.org/node/184354
http://secunia.com/advisories/12160
http://secunia.com/advisories/27292
http://sunsolve.sun.com/search/document.do?assetkey=1-26-57591-1&amp;searchclause=%22category:security%22%20%22availability,%20security%22
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
http://www.securityfocus.com/archive/1/382072');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/ac619d06-3ef8-11d9-8741-c942c075aa41.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_cvs_date("$Date: 2011/10/03 00:48:25 $");
 script_end_attributes();
 script_summary(english:"Check for diablo-jdk");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37437 (freebsd_pkg_ac619d063ef811d98741c942c075aa41.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"jdk>=1.4.0<=1.4.2p6_6");

pkg_test(pkg:"jdk>=1.3.0<=1.3.1p9_5");

pkg_test(pkg:"linux-jdk>=1.4.0<=1.4.2.05");

pkg_test(pkg:"linux-jdk>=1.3.0<=1.3.1.13");

pkg_test(pkg:"linux-sun-jdk>=1.4.0<=1.4.2.05");

pkg_test(pkg:"linux-sun-jdk>=1.3.0<=1.3.1.13");

pkg_test(pkg:"linux-blackdown-jdk>=1.3.0<=1.4.2");

pkg_test(pkg:"linux-ibm-jdk>=1.3.0<=1.4.2");

pkg_test(pkg:"diablo-jdk>=1.3.1.0<=1.3.1.0_1");

pkg_test(pkg:"diablo-jre>=1.3.1.0<=1.3.1.0_1");
