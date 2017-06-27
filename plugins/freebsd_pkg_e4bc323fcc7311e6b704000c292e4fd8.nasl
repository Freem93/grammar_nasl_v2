#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(96164);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");

  script_name(english:"FreeBSD : samba -- multiple vulnerabilities (e4bc323f-cc73-11e6-b704-000c292e4fd8)");
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
"Samba team reports :

[CVE-2016-2123] Authenicated users can supply malicious dnsRecord
attributes on DNS objects and trigger a controlled memory corruption.

[CVE-2016-2125] Samba client code always requests a forwardable ticket
when using Kerberos authentication. This means the target server,
which must be in the current or trusted domain/realm, is given a valid
general purpose Kerberos 'Ticket Granting Ticket' (TGT), which can be
used to fully impersonate the authenticated user or service.

[CVE-2016-2126] A remote, authenticated, attacker can cause the
winbindd process to crash using a legitimate Kerberos ticket due to
incorrect handling of the PAC checksum. A local service with access to
the winbindd privileged pipe can cause winbindd to cache elevated
access permissions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2123.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2126.html"
  );
  # http://www.freebsd.org/ports/portaudit/e4bc323f-cc73-11e6-b704-000c292e4fd8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c21320e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba45");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"samba36>=3.6.0<=3.6.25_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba4>=4.0.0<=4.0.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba41>=4.1.0<=4.1.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba42>=4.2.0<=4.2.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba43>=4.3.0<4.3.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba44>=4.4.0<4.4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba45>=4.5.0<4.5.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
