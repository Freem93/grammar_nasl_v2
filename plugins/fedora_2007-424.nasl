#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-424.
#

include("compat.inc");

if (description)
{
  script_id(25027);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:01 $");

  script_xref(name:"FEDORA", value:"2007-424");

  script_name(english:"Fedora Core 5 : xorg-x11-server-1.0.1-9.fc5.7 (2007-424)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sun Apr 8 2007 Adam Jackson <ajax at redhat.com>
    1.0.1-9.fc5.7

    - xserver-CVE-2007-1003.patch: Fix CVE-2007-1003 in
      XC-MISC extension.

    - xorg-x11-server-1.0.1-intel-bridge-fix.patch: Backport
      an Intel PCI bridge fix from FC6.

  - Tue Jan 9 2007 Adam Jackson <ajax at redhat.com>
    1.0.1-9.fc5.6

    - xorg-xserver-1.0.1-dbe-render.diff: CVE #2006-6101.

    - Fri Jun 30 2006 Mike A. Harris <mharris at redhat.com>
      1.0.1-9.fc5.5

    - Standardize on using lowercase 'fcN' in Release field
      to denote the OS release the package is being built
      for in all erratum from now on, as this is the
      official Fedora packaging guideline recommended way
      that the new 'dist' tag uses:
      http://fedoraproject.org/wiki/DistTag. (#197266)

  - Remove various rpm spec file macros from the changelog
    which were inadvertently added over time. (#197281)

  - Mon Jun 26 2006 Mike A. Harris <mharris at redhat.com>
    1.0.1-9.FC5.4

    - Updated build dependency to require
      mesa-source-6.4.2-6.FC5.3 minimum for DRI enabled
      builds to fix numerous bug reports on x86_64 including
      (#190245, 185929,187603,185727,189730)

  - Added xorg-x11-server-1.0.1-setuid.diff to fix setuid
    bug (#196126)

    - Bump xtrans dependency to '>= 1.0.0-3.2.FC5.0' for
      setuid fix in xtrans.

    - Added 'BuildRequires: freetype-devel >= 2.1.9-1,
      zlib-devel' so that the package will build now in
      brew/mock for erratum.

  - Fri May 19 2006 Mike A. Harris <mharris at redhat.com>
    1.0.1-9.FC5.3

    - Enable alpha, sparc, sparc64 architectures to be
      buildable (untested, but feel free to submit patches
      in bugzilla if it does not work right)

  - Add missing SBUS header for sparc architecture (#187357)

    - Fri May 5 2006 Mike A. Harris <mharris at redhat.com>
      1.0.1-9.fc5.2

    - Merge
      xorg-x11-server-1.0.1-render-tris-CVE-2006-1526.patch
      security fix from 1.0.1-9.fc5.1.1 release from
      embargoed branch of CVS to FC-5 branch.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://fedoraproject.org/wiki/DistTag."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-April/001651.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80a79938"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xdmx-1.0.1-9.fc5.7")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xnest-1.0.1-9.fc5.7")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xorg-1.0.1-9.fc5.7")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xvfb-1.0.1-9.fc5.7")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-debuginfo-1.0.1-9.fc5.7")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-sdk-1.0.1-9.fc5.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xnest / xorg-x11-server-Xorg / etc");
}
