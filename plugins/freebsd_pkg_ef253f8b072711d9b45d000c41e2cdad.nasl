#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(19161);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/06/22 00:15:01 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_xref(name:"CERT", value:"537878");
  script_xref(name:"CERT", value:"882750");

  script_name(english:"FreeBSD : xpm -- image decoding vulnerabilities (ef253f8b-0727-11d9-b45d-000c41e2cdad)");
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
"Chris Evans discovered several vulnerabilities in the libXpm image
decoder :

- A stack-based buffer overflow in xpmParseColors

- An integer overflow in xpmParseColors

- A stack-based buffer overflow in ParsePixels and ParseAndPutPixels

The X11R6.8.1 release announcement reads :

This version is purely a security release, addressing multiple integer
and stack overflows in libXpm, the X Pixmap library; all known
versions of X (both XFree86 and X.Org) are affected, so all users of X
are strongly encouraged to upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freedesktop.org/pipermail/xorg/2004-September/003172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://scary.beasts.org/security/CESA-2004-003.txt"
  );
  # http://www.freebsd.org/ports/portaudit/ef253f8b-0727-11d9-b45d-000c41e2cdad.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88ad7e5a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:XFree86-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:agenda-snow-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-openmotif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux_base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mupad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:open-motif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:open-motif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-cle_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"agenda-snow-libs>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux_base>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"open-motif-devel>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mupad>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-cle_base>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXpm<3.5.1_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"XFree86-libraries<4.4.0_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xorg-libraries<6.7.0_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"lesstif<0.93.96,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xpm<3.4k_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-openmotif<2.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"open-motif<2.2.3_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
