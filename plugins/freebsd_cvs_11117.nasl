# @DEPRECATED@
# 
# This script has been deprecated by freebsd_pkg_d2102505f03d11d881b0000347a4fa7d.nasl.
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
 script_id(14282);
 script_version("$Revision: 1.25 $");
 script_bugtraq_id(10499);

 script_name(english:"FreeBSD : cvs -- numerous vulnerabilities (29)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: FreeBSD');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/11817
http://secunia.com/advisories/12309
http://security.e-matters.de/advisories/092004.html
http://www.idefense.com/application/poi/display?id=130&amp;type=vulnerabilities&amp;flashstatus=false
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.osvdb.org/6830
http://www.osvdb.org/6831
http://www.osvdb.org/6832
http://www.osvdb.org/6833
http://www.osvdb.org/6834
http://www.osvdb.org/6835
http://www.osvdb.org/6836
https://ccvs.cvshome.org/source/browse/ccvs/NEWS?rev=1.116.2.104');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/d2102505-f03d-11d8-81b0-000347a4fa7d.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_cvs_date("$Date: 2011/10/02 00:58:57 $");
 script_end_attributes();
 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-0778", "CVE-2004-1471");
 script_summary(english:"Check for FreeBSD");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated. Refer to plugin #37427 (freebsd_pkg_d2102505f03d11d881b0000347a4fa7d.nasl) instead.");


global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"cvs+ipv6<1.11.17");

pkg_test(pkg:"FreeBSD<491101");

pkg_test(pkg:"FreeBSD>=500000<502114");
