# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_992302778fb411d88b290020ed76ef5a.nasl.
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
 script_id(12553);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0408");

 script_name(english:"FreeBSD : ident2 double byte buffer overflow (72)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: ident2');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/iso2022jp.c?rev=1.10&amp;view=markup
http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/shiftjis.c?rev=1.6&amp;view=markup
http://cvsweb.freebsd.org/ports/security/ident2/files/patch-common.c
http://secunia.com/advisories/11087
http://secunia.com/advisories/26224/
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.mozilla.org/security/announce/2006/mfsa2006-18.html
http://www.mozilla.org/security/announce/2006/mfsa2006-19.html
http://www.mozilla.org/security/announce/2006/mfsa2006-20.html
http://www.mozilla.org/security/announce/2009/mfsa2009-01.html
http://www.mozilla.org/security/announce/2009/mfsa2009-02.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/99230277-8fb4-11d8-8b29-0020ed76ef5a.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();
 script_summary(english:"Check for ident2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36517 (freebsd_pkg_992302778fb411d88b290020ed76ef5a.nasl) instead.");

global_var cvss_score;
cvss_score=7;
include('freebsd_package.inc');


pkg_test(pkg:"ident2<=1.04");
