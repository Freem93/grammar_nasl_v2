# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_f9e3e60be65011d89b0a000347a4fa7d.nasl.
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
 script_id(14216);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0599");
 script_cve_id("CVE-2004-0598");
 script_cve_id("CVE-2004-0597");

 script_name(english:"FreeBSD : libpng stack-based buffer overflow and other code concerns (94)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: firefox');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugzilla.mozilla.org/show_bug.cgi?id=251381
http://dl.sourceforge.net/sourceforge/libpng/ADVISORY.txt
http://scary.beasts.org/security/CESA-2004-001.txt
http://secunia.com/advisories/12219
http://secunia.com/advisories/12232
http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey1.0.3
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-44.html
http://www.mozilla.org/security/announce/2008/mfsa2008-47.html
http://www.mozilla.org/security/announce/2008/mfsa2008-48.html
http://www.osvdb.org/8312
http://www.osvdb.org/8313
http://www.osvdb.org/8314
http://www.osvdb.org/8315
http://www.osvdb.org/8316');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/f9e3e60b-e650-11d8-9b0a-000347a4fa7d.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/06");
 script_end_attributes();
 script_summary(english:"Check for firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36897 (freebsd_pkg_f9e3e60be65011d89b0a000347a4fa7d.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"png<=1.2.5_7");

pkg_test(pkg:"linux-png<=1.0.14_3");

pkg_test(pkg:"linux-png>=1.2.*<=1.2.2");

pkg_test(pkg:"firefox<0.9.3");

pkg_test(pkg:"thunderbird<0.7.3");

pkg_test(pkg:"linux-mozilla<1.7.2");

pkg_test(pkg:"linux-mozilla-devel<1.7.2");

pkg_test(pkg:"mozilla<1.7.2,2");

pkg_test(pkg:"mozilla>=1.8.*,2<=1.8.a2,2");

pkg_test(pkg:"mozilla-gtk1<1.7.2");

pkg_test(pkg:"netscape-{communicator,navigator}<=4.78");

pkg_test(pkg:"linux-netscape-{communicator,navigator}<=4.8");

pkg_test(pkg:"{ja,ko}-netscape-{communicator,navigator}-linux<=4.8");

pkg_test(pkg:"{,ja-}netscape7<=7.1");

pkg_test(pkg:"{de-,fr-,pt_BR-}netscape7<=7.02");
