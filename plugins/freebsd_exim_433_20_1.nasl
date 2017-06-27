# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_5f29c2e49f6a11d8abbc00e08110b673.nasl.
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
 script_id(12538);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0400");

 script_name(english:"FreeBSD : exim buffer overflow when verify = header_syntax is used (43)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: exim-ldap2');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.guninski.com/exim1.html
http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/mfsa2005-45.html
http://www.mozilla.org/security/announce/mfsa2005-46.html
http://www.mozilla.org/security/announce/mfsa2005-47.html
http://www.mozilla.org/security/announce/mfsa2005-48.html
http://www.mozilla.org/security/announce/mfsa2005-49.html
http://www.mozilla.org/security/announce/mfsa2005-50.html
http://www.mozilla.org/security/announce/mfsa2005-51.html
http://www.mozilla.org/security/announce/mfsa2005-52.html
http://www.mozilla.org/security/announce/mfsa2005-53.html
http://www.mozilla.org/security/announce/mfsa2005-54.html
http://www.mozilla.org/security/announce/mfsa2005-55.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/5f29c2e4-9f6a-11d8-abbc-00e08110b673.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();
 script_summary(english:"Check for exim-ldap2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36893 (freebsd_pkg_5f29c2e49f6a11d8abbc00e08110b673.nasl) instead.");

global_var cvss_score;
cvss_score=7;
include('freebsd_package.inc');


pkg_test(pkg:"exim<4.33+20_1");

pkg_test(pkg:"exim-ldap2<4.33+20_1");

pkg_test(pkg:"exim-mysql<4.33+20_1");

pkg_test(pkg:"exim-postgresql<4.33+20_1");
