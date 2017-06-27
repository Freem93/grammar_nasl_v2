#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-25.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22287);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:51 $");

  script_cve_id("CVE-2006-4447");
  script_osvdb_id(28239);
  script_xref(name:"GLSA", value:"200608-25");

  script_name(english:"GLSA-200608-25 : X.org and some X.org libraries: Local privilege escalations");
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
"The remote host is affected by the vulnerability described in GLSA-200608-25
(X.org and some X.org libraries: Local privilege escalations)

    Several X.org libraries and X.org itself contain system calls to
    set*uid() functions, without checking their result.
  
Impact :

    Local users could deliberately exceed their assigned resource limits
    and elevate their privileges after an unsuccessful set*uid() system
    call. This requires resource limits to be enabled on the machine.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.freedesktop.org/archives/xorg/2006-June/016146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.Org xdm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xdm-1.0.4-r1'
    All X.Org xinit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xinit-1.0.2-r6'
    All X.Org xload users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xload-1.0.1-r1'
    All X.Org xf86dga users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-apps/xf86dga-1.0.1-r1'
    All X.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-x11-6.9.0-r2'
    All X.Org X servers users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.1.0-r1'
    All X.Org X11 library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/libx11-1.0.1-r1'
    All X.Org xtrans library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/xtrans-1.0.1-r1'
    All xterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/xterm-215'
    All users of the X11R6 libraries for emulation of 32bit x86 on amd64
    should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-xlibs-7.0-r2'
    Please note that the fixed packages have been available for most
    architectures since June 30th but the GLSA release was held up waiting
    for the remaining architectures."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-xlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libx11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xtrans");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-base/xorg-server", unaffected:make_list("rge 1.0.2-r6", "ge 1.1.0-r1"), vulnerable:make_list("lt 1.1.0-r1"))) flag++;
if (qpkg_check(package:"x11-apps/xf86dga", unaffected:make_list("ge 1.0.1-r1"), vulnerable:make_list("lt 1.0.1-r1"))) flag++;
if (qpkg_check(package:"x11-apps/xinit", unaffected:make_list("ge 1.0.2-r6"), vulnerable:make_list("lt 1.0.2-r6"))) flag++;
if (qpkg_check(package:"x11-apps/xdm", unaffected:make_list("ge 1.0.4-r1"), vulnerable:make_list("lt 1.0.4-r1"))) flag++;
if (qpkg_check(package:"x11-libs/xtrans", unaffected:make_list("ge 1.0.0-r1"), vulnerable:make_list("lt 1.0.0-r1"))) flag++;
if (qpkg_check(package:"x11-terms/xterm", unaffected:make_list("ge 215"), vulnerable:make_list("lt 215"))) flag++;
if (qpkg_check(package:"x11-libs/libx11", unaffected:make_list("ge 1.0.1-r1"), vulnerable:make_list("lt 1.0.1-r1"))) flag++;
if (qpkg_check(package:"x11-apps/xload", unaffected:make_list("ge 1.0.1-r1"), vulnerable:make_list("lt 1.0.1-r1"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-xlibs", arch:"amd64", unaffected:make_list("ge 7.0-r2"), vulnerable:make_list("lt 7.0-r2"))) flag++;
if (qpkg_check(package:"x11-base/xorg-x11", unaffected:make_list("rge 6.8.2-r8", "ge 6.9.0-r2"), vulnerable:make_list("lt 6.9.0-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.org and some X.org libraries");
}
