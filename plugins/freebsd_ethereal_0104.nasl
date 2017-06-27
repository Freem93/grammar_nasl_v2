# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_74d06b67d2cf11d8b47902e0185c0b53.nasl.
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
 script_id(12645);
 script_version("$Revision: 1.15 $");
 script_bugtraq_id(10347);
 script_cve_id("CVE-2004-0507");
 script_cve_id("CVE-2004-0506");
 script_cve_id("CVE-2004-0505");
 script_cve_id("CVE-2004-0504");

 script_name(english:"FreeBSD : multiple vulnerabilities in ethereal (41)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: ethereal');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.libgd.org/?do=details&amp;task_id=89
http://bugs.libgd.org/?do=details&amp;task_id=94
http://secunia.com/advisories/11608
http://www.ethereal.com/appnotes/enpa-sa-00014.html
http://www.frsirt.com/english/advisories/2007/2336
http://www.libgd.org/ReleaseNote020035
http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/mfsa2005-46.html
http://www.mozilla.org/security/announce/mfsa2005-47.html
http://www.osvdb.org/6131
http://www.osvdb.org/6132
http://www.osvdb.org/6133
http://www.osvdb.org/6134');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/74d06b67-d2cf-11d8-b479-02e0185c0b53.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/11");
 script_cvs_date("$Date: 2011/10/03 00:48:25 $");
 script_end_attributes();
 script_summary(english:"Check for ethereal");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37398 (freebsd_pkg_74d06b67d2cf11d8b47902e0185c0b53.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"ethereal{,-lite}<0.10.4");

pkg_test(pkg:"tethereal{,-lite}<0.10.4");
