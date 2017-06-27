#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-618.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25620);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-618");

  script_name(english:"Fedora Core 5 : gimp-2.2.15-3.fc5 (2007-618)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jun 27 2007 Nils Philippsen <nphilipp at redhat.com>
    - 2:2.2.15-3

    - refuse to open PSD files with insanely large
      dimensions (#244402, fix by Sven Neumann)

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

    - Tue May 1 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.14-5

    - don't let gimp-plugin-mgr --uninstall fail %pre/%preun
      scriptlets (#238337)

    - Mon Apr 30 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.14-4

    - fix plugin symlinks handling better (#238337)

    - Mon Apr 30 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.14-3

    - don't erroneously delete symlinks to external plugins
      when updating (#238337)

    - Mon Apr 30 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.14-2

    - avoid buffer overflow in sunras plugin (#238422)

    - Tue Apr 24 2007 Nils Philippsen <nphilipp at
      redhat.com> - 2:2.2.14-1

    - version 2.2.14 Bugs fixed in GIMP 2.2.14
      =========================

  - avoid crashing on newer versions of the winicon format
    (bug #352899)

    - fixed crash in Postscript plug-in (bug #353381)

    - fixed handling of TABs in the text tool (bug #353132)

    - fixed bug in Depth Merge plug-in (bug #355219)

    - fixed bug in GimpDrawablePreview widget (bug #353639)

    - fixed bug in Line Nove script (bug #357433)

    - fixed bug in Ripple plug-in (bug #357431)

    - save locale independent files from Fractal Explorer
      plug-in (bug #360095)

    - fixed bug in Super Nova plug-in (bug #340073)

    - be more robust against broken XCF files (bug #357809)

    - fixed drawing issues in Image Map plug-in (bug
      #311621)

    - fixed smoothing option in Fractal Explorer plug-in
      (bug #372671)

    - load channels in the proper order when opening an XCF
      file (bug #378003)

    - deal with floating selections in the Burn-In Animation
      script (bug #384096)

    - fixed clipping in the GimpPreviewArea widget (bug
      #392692)

    - fixed a potential crash in gimp-remote (bug #392111)

[plus 47 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-June/002434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73003e48"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");
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
if (rpm_check(release:"FC5", reference:"gimp-2.2.15-3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"gimp-debuginfo-2.2.15-3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"gimp-devel-2.2.15-3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"gimp-libs-2.2.15-3.fc5")) flag++;


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
