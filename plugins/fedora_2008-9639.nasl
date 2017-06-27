#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9639.
#

include("compat.inc");

if (description)
{
  script_id(34761);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:32:47 $");

  script_xref(name:"FEDORA", value:"2008-9639");

  script_name(english:"Fedora 8 : optipng-0.6.2-1.fc8 (2008-9639)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The main reason for this update is a buffer overflow that is removed
in this version, that could be triggered by processing specially
crafted bitmap images (*.bmp). Aggregated upstream changelog:
============================== ++ Put back a speed optimization,
accidentally removed in version 0.6, allowing singleton trials (-o1)
to be bypassed in certain conditions. !! Fixed an array overflow in
the BMP reader. !! Fixed the loss of private chunks under the -snip
option. + Produced a more concise on-screen output in the non-verbose
mode. (Thanks to Vincent Lefevre for the suggestion.) * Added a
programming interface to the optimization engine, in order to
facilitate the development of PNG- optimizing GUI apps and plugins. !
Fixed processing when image reduction yields an output larger than the
original. (Thanks to Michael Krishtopa for the report.) ! Fixed
behavior of -preserve. (Thanks to Bill Koch for the report.)

  - Removed displaying of partial progress when abandoning
    IDATs under the -v option. The percentages displayed
    were not very accurate. ++ Implemented
    grayscale(alpha)-to-palette reductions. ++ Improved
    conversion of bKGD info during RGB-to-palette
    reductions. (Thanks to Matthew Fearnley for the
    contribution.) !! Fixed conversion of bKGD and tRNS
    during 16-to-8-bit reductions. (Thanks to Matthew
    Fearnley for the report.) + Added support for compressed
    BMP (incl. PNG-compressed BMP, you bet!) + Improved the
    speed of reading raw PNM files. + Recognized PNG digital
    signatures (dSIG) and disabled optimization in their
    presence, to preserve their integrity. + Allowed the
    user to enforce the optimization of dSIG'ed files. +
    Recognized APNG animation files and disabled reductions
    to preserve their integrity. + Added the -snip option,
    to allow the user to 'snip' one image out of a
    multi-image file, such as animated GIF, multi-page TIFF,
    or APNG. (Thanks to [LaughingMan] for the suggestion.) +
    Improved recovery of PNG files with incomplete IDAT. !
    Fixed behavior of -out and -dir when the input is
    already optimized. (Thanks to Christian Davideck for the
    report.) * Provided more detailed image information at
    the start of processing. * Provided a more detailed
    summary at the end of processing, under the presence of
    the -v option and/or the occurence of exceptional
    events.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=471206"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?568efc04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected optipng package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:optipng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"optipng-0.6.2-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "optipng");
}
