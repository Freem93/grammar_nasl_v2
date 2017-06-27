#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-11880.
#

include("compat.inc");

if (description)
{
  script_id(44877);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/21 22:32:49 $");

  script_xref(name:"FEDORA", value:"2009-11880");

  script_name(english:"Fedora 11 : gimp-2.6.8-1.fc11 (2009-11880)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Overview of Changes from GIMP 2.6.7 to GIMP 2.6.8
================================================= * Bugs fixed: 470698
- MapObject cannot modify highlight 593848 - FG color changed to black
when FG- BG Editor tab created 594651 - layer.scale() raises
RuntimeError 594998 - Keyboard shortcuts does not work for first image
when dock is focused 599765 - F1 key on gimp-tool-align in menu have
wrong link and it open gimp-tool-move 600484 - Gimp BMP Integer
Overflow Vulnerability 600741

  - 'read_channel_data()' Integer Overflow Vulnerability
    601891 - gimp_image_get_selection returns None 602761 -
    plug-in-grid: Parameters Horizontal/Vertical Spacing and
    Horizontal/Vertical Offset are reversed. 603995 - PCX
    plugin doesn't sanitize input to avoid allocation
    overflows. 603998 - PCX: Calculating amount of memory to
    allocate may overflow. 604000 - SGI: sanitize input
    604001 - SGI: Calculating amount of memory to allocate
    may overflow. 604002 - SGI: RLE encoded input data may
    write beyond allocated buffers 604004 - SGI: allocate
    memory consistently 604008 - GBR, PAT: sanitize input
    data 604078 - Crash when pressing Backspace with Free
    Select Tool * Updated and new translations: Basque (eu)
    British English (en_GB) Czech (cs) French (fr) Greek
    (el) Italian (it) Japanese (ja) Norwegian Nynorsk (nn)
    Polish (pl) Romanian (ro) Russian (ru) Simplified
    Chinese (zh_CN) For more information about the above
    bugs, please consult the respective tickets on:
    http://bugzilla.gnome.org

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.gnome.org"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-January/033507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d72063f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"gimp-2.6.8-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp");
}
