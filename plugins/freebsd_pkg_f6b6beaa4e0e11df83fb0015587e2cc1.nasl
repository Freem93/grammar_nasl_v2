# @DEPRECATED@
#
# This script has been deprecated as the VuXML entry has been 
# cancelled.
#
# Disabled on 2011/10/02.

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
 script_id(45616);
 script_version("$Revision: 1.2 $");
 script_cve_id("CVE-2010-0825");

 script_name(english:"FreeBSD : emacs -- movemail symlink race condition (5253)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: emacs');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/39155
http://www.ubuntu.com/usn/USN-919-1
http://www.vupen.com/english/advisories/2010/0734
http://xforce.iss.net/xforce/xfdb/57457
https://bugs.launchpad.net/ubuntu/+bug/531569');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/f6b6beaa-4e0e-11df-83fb-0015587e2cc1.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/26");
 script_cvs_date("$Date: 2011/10/03 01:28:59 $");
 script_end_attributes();
 script_summary(english:"Check for emacs");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated as the associated VuXML entry has been cancelled.");

global_var cvss_score;
cvss_score=4;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"movemail<=1.0");

holes_nb += pkg_test(pkg:"emacs<=21.3_14");

holes_nb += pkg_test(pkg:"emacs>=22.3_1,1<=22.3_4,1");

holes_nb += pkg_test(pkg:"emacs>=23.1<=23.1_5,1");

holes_nb += pkg_test(pkg:"xemacs<=21.4.22_4");

holes_nb += pkg_test(pkg:"xemacs-devel<=21.5.b28_8,1");

holes_nb += pkg_test(pkg:"xemacs-mule<=21.4.21_6");

holes_nb += pkg_test(pkg:"zh-xemacs-mule<=21.4.21_6");

holes_nb += pkg_test(pkg:"ja-xemacs-mule-canna<=21.4.21_6");

holes_nb += pkg_test(pkg:"xemacs-devel-mule<=21.5.b28_10");

holes_nb += pkg_test(pkg:"xemacs-devel-mule-xft<=21.5.b28_10");

if (holes_nb == 0) exit(0,"Host is not affected");
