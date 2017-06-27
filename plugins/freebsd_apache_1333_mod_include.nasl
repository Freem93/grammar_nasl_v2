# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_6e6a6b8a2fde11d9b3a20050fc56d258.nasl.
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
 script_id(15797);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0940");

 script_name(english:"FreeBSD : apache mod_include buffer overflow vulnerability (11)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: apache+ipv6');
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_cwe_id(119);
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.libgd.org/?do=details&amp;task_id=70
http://bugs.libgd.org/?do=details&amp;task_id=87
http://bugs.libgd.org/?do=details&amp;task_id=89
http://bugs.libgd.org/?do=details&amp;task_id=92
http://bugs.libgd.org/?do=details&amp;task_id=94
http://www.bugzilla.org/security/2.18.1/
http://www.frsirt.com/english/advisories/2007/2336
http://www.libgd.org/ReleaseNote020035
http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/mfsa2005-46.html
http://www.mozilla.org/security/announce/mfsa2005-47.html
http://www.securitylab.ru/48807.html
https://bugzilla.mozilla.org/show_bug.cgi?id=292544');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/6e6a6b8a-2fde-11d9-b3a2-0050fc56d258.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/23");
 script_cvs_date("$Date: 2011/10/03 00:48:24 $");
 script_end_attributes();
 script_summary(english:"Check for apache+ipv6");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37841 (freebsd_pkg_6e6a6b8a2fde11d9b3a20050fc56d258.nasl) instead.");

global_var cvss_score;
cvss_score=6;
include('freebsd_package.inc');


pkg_test(pkg:"apache<1.3.33");

pkg_test(pkg:"apache+mod_ssl<1.3.32+2.8.21_1");

pkg_test(pkg:"apache+mod_ssl+ipv6<1.3.32+2.8.21_1");

pkg_test(pkg:"apache+mod_perl<=1.3.31");

pkg_test(pkg:"apache+ipv6<1.3.33");

pkg_test(pkg:"apache+ssl<=1.3.29.1.55");

pkg_test(pkg:"ru-apache<1.3.33+30.21");

pkg_test(pkg:"ru-apache+mod_ssl<1.3.33+30.21+2.8.22");
