#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-1099.
#

include("compat.inc");

if (description)
{
  script_id(27690);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_xref(name:"FEDORA", value:"2007-1099");

  script_name(english:"Fedora 7 : gimp-2.2.17-1.fc7 (2007-1099)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Jul 13 2007 Nils Philippsen <nphilipp at redhat.com>
    - 2:2.2.17-1

    - version 2.2.17

      Bugs fixed in GIMP 2.2.17 =========================

  - fixed regression in PSD load plug-in (bug #456042)

    - fixed crash when loading a corrupt PSD file (bug
      #327444)

    - work around for Pango appending ' Not-Rotated' to font
      names

    - Wed Jul 11 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.16-2

    - don't let gimp-plugin-mgr --uninstall fail %post
      scriptlet

    - Mon Jul 9 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.16-1

    - version 2.2.16

      Bugs fixed in GIMP 2.2.16 =========================

  - improved input value validation in several file plug-ins
    (bug #453973)

    - improved handling of corrupt or invalid XCF files

    - guard against integer overflows in several file
      plug-ins (bug #451379)

    - fixed handling of background alpha channel in XCF
      files (bug #443097)

    - improved forward compatibility of the config parser

    - fixed crash when previewing some animated brushes (bug
      #446005)

  - remove obsolete psd-invalid-dimensions patch

    - Wed Jun 27 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.15-3

    - refuse to open PSD files with insanely large
      dimensions (#244400, fix by Sven Neumann)

  - Wed Jun 13 2007 Nils Philippsen <nphilipp at redhat.com>
    - 2:2.2.15-2

    - require gutenprint-plugin or gimp-print-plugin
      (#243593)

    - Thu May 31 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.15-1

    - version 2.2.15

      Bugs fixed in GIMP 2.2.15 =========================

  - fixed parsing of GFig files with CRLF line endings (bug
    #346988)

    - guard against a possible stack overflow in the Sunras
      loader (bug #433902)

    - fixed definition of datarootdir in gimptool-2.0 (bug
      #436386)

    - fixed Perspective tool crash on Mac OS X (bug #349483)

    - fixed area resizing in the Image Map plug-in (bug
      #439222)

    - added missing library in gimptool-2.0 --libs output

    - added new localizations: Occitan and Persian

  - remove obsolete sunras-overflow patch

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-July/002776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9383c45"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"gimp-2.2.17-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gimp-debuginfo-2.2.17-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gimp-devel-2.2.17-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gimp-libs-2.2.17-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-devel / gimp-libs");
}
