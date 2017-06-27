# @DEPRECATED@
# 
# This script has been deprecated by freebsd_pkg_0c4d5973f2ab11d89837000c41e2cdad.nasl.
#
# Disabled on 2011/10/01.

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
 script_id(14339);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0457");

 script_name(english:"FreeBSD : mysql -- mysqlhotcopy insecure temporary file creation (125)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: mysql-scripts');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.debian.org/security/2004/dsa-540
http://www.mantisbt.org/bugs/view.php?id=9533
http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE10-STORE_PENDING
http://www.squid-cache.org/bugs/show_bug.cgi?id=1368');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/0c4d5973-f2ab-11d8-9837-000c41e2cdad.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_end_attributes();
 script_summary(english:"Check for mysql-scripts");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated. Refer to plugin #37724 (freebsd_pkg_0c4d5973f2ab11d89837000c41e2cdad.nasl) instead.");

global_var cvss_score;
cvss_score=4;
include('freebsd_package.inc');


pkg_test(pkg:"mysql-scripts<=3.23.58");

pkg_test(pkg:"mysql-scripts>4<=4.0.20");

pkg_test(pkg:"mysql-scripts>4.1<=4.1.3");

pkg_test(pkg:"mysql-scripts>5<=5.0.0_1");
