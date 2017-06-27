# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_3243e839f48911d89837000c41e2cdad.nasl.
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
 script_id(14341);
 script_version("$Revision: 1.10 $");

 script_name(english:"FreeBSD : fidogate -- write files as `news' user (49)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: fidogate-ds');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://cvs.sourceforge.net/viewcvs.py/fidogate/fidogate/ChangeLog?rev=4.320&amp;view=markup
http://docs.info.apple.com/article.html?artnum=61798
http://www.mozilla.org/security/announce/2008/mfsa2008-60.html
http://www.mozilla.org/security/announce/2008/mfsa2008-61.html
http://www.mozilla.org/security/announce/2008/mfsa2008-62.html
http://www.mozilla.org/security/announce/2008/mfsa2008-63.html
http://www.mozilla.org/security/announce/2008/mfsa2008-64.html
http://www.opera.com/docs/changelogs/freebsd/925/
http://www.opera.com/docs/changelogs/freebsd/926/
http://www.samba.org/samba/whatsnew/samba-3.0.5.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/3243e839-f489-11d8-9837-000c41e2cdad.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_end_attributes();
 script_summary(english:"Check for fidogate-ds");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37125 (freebsd_pkg_3243e839f48911d89837000c41e2cdad.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"fidogate<4.4.9_3");

pkg_test(pkg:"fidogate-ds<5.1.1_1");
