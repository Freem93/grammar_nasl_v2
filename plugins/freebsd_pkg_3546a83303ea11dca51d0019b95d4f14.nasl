#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
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

include("compat.inc");

if (description)
{
  script_id(25260);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");

  script_name(english:"FreeBSD : samba -- multiple vulnerabilities (3546a833-03ea-11dc-a51d-0019b95d4f14)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Samba Team reports :

A bug in the local SID/Name translation routines may potentially
result in a user being able to issue SMB/CIFS protocol operations as
root.

When translating SIDs to/from names using Samba local list of user and
group accounts, a logic error in the smbd daemon's internal security
stack may result in a transition to the root user id rather than the
non-root user. The user is then able to temporarily issue SMB/CIFS
protocol operations as the root user. This window of opportunity may
allow the attacker to establish additional means of gaining root
access to the server.

Various bugs in Samba's NDR parsing can allow a user to send specially
crafted MS-RPC requests that will overwrite the heap space with user
defined data.

Unescaped user input parameters are passed as arguments to /bin/sh
allowing for remote command execution.

This bug was originally reported against the anonymous calls to the
SamrChangePassword() MS-RPC function in combination with the 'username
map script' smb.conf option (which is not enabled by default).

After further investigation by Samba developers, it was determined
that the problem was much broader and impacts remote printer and file
share management as well. The root cause is passing unfiltered user
input provided via MS-RPC calls to /bin/sh when invoking externals
scripts defined in smb.conf. However, unlike the 'username map script'
vulnerability, the remote file and printer management scripts require
an authenticated user session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://de5.samba.org/samba/security/CVE-2007-2444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://de5.samba.org/samba/security/CVE-2007-2446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://de5.samba.org/samba/security/CVE-2007-2447.html"
  );
  # http://www.freebsd.org/ports/portaudit/3546a833-03ea-11dc-a51d-0019b95d4f14.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ca1b435"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"samba>3.*<3.0.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba>3.*,1<3.0.25,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-samba>3.*<3.0.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-samba>3.*,1<3.0.25,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
