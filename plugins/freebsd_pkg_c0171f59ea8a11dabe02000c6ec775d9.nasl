#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(21591);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2006-0015");

  script_name(english:"FreeBSD : frontpage -- XSS vulnerability (c0171f59-ea8a-11da-be02-000c6ec775d9)");
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
"Esteban Martinez Fayo reports :

The FrontPage Server Extensions 2002 (included in Windows Sever 2003
IIS 6.0 and available as a separate download for Windows 2000 and XP)
has a web page /_vti_bin/_vti_adm/fpadmdll.dll that is used for
administrative purposes. This web page is vulnerable to cross site
scripting attacks allowing an attacker to run client-side script on
behalf of an FPSE user. If the victim is an administrator, the
attacker could take complete control of a Front Page Server Extensions
2002 server.

To exploit the vulnerability an attacker can send a specially crafted
e-mail message to a FPSE user and then persuade the user to click a
link in the e-mail message.

In addition, this vulnerability can be exploited if an attacker hosts
a malicious website and persuade the user to visit it."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=114487846329000
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=114487846329000"
  );
  # http://www.microsoft.com/technet/security/bulletin/MS06-017.mspx
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-017"
  );
  # http://www.rtr.com/fpsupport/fpse_release_may_2_2006.htm
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?909c12a8"
  );
  # http://www.freebsd.org/ports/portaudit/c0171f59-ea8a-11da-be02-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24e60a67"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:frontpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_frontpage13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_frontpage20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_frontpage21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_frontpage22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"frontpage<5.0.2.4803")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_frontpage13<5.0.2.4803")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_frontpage20<5.0.2.4803")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_frontpage21<5.0.2.4803")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_frontpage22<5.0.2.4803")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
