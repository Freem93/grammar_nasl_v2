#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-34.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14821);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_osvdb_id(10026, 10027, 10028, 10029, 10030, 10031, 10032, 10033, 10034);
  script_xref(name:"GLSA", value:"200409-34");

  script_name(english:"GLSA-200409-34 : X.org, XFree86: Integer and stack overflows in libXpm");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200409-34
(X.org, XFree86: Integer and stack overflows in libXpm)

    Chris Evans has discovered multiple integer and stack overflow
    vulnerabilities in the X Pixmap library, libXpm, which is a part of the
    X Window System. These overflows can be exploited by the execution of a
    malicious XPM file, which can crash applications that are dependent on
    libXpm.
  
Impact :

    A carefully-crafted XPM file could crash applications that are linked
    against libXpm, potentially allowing the execution of arbitrary code
    with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freedesktop.org/pipermail/xorg/2004-September/003196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://freedesktop.org/pipermail/xorg/2004-September/003172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-34"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.org users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=x11-base/xorg-x11-6.7.0-r2'
    # emerge '>=x11-base/xorg-x11-6.7.0-r2'
    All XFree86 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=x11-base/xfree-4.3.0-r7'
    # emerge '>=x11-base/xfree-4.3.0-r7'
    Note: Usage of XFree86 is deprecated on the AMD64, HPPA, IA64, MIPS,
    PPC and SPARC architectures: XFree86 users on those architectures
    should switch to X.org rather than upgrading XFree86."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);


flag = 0;

if (qpkg_check(package:"x11-base/xfree", arch:"amd64 hppa ia64 mips ppc sparc", unaffected:make_list(), vulnerable:make_list("lt 4.3.0-r7"))) flag++;
if (qpkg_check(package:"x11-base/xorg-x11", unaffected:make_list("rge 6.7.0-r2", "ge 6.8.0-r1"), vulnerable:make_list("lt 6.7.0-r2", "eq 6.8.0"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.org / XFree86");
}
