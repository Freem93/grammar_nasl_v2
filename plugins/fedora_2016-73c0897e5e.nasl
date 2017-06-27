#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-73c0897e5e.
#

include("compat.inc");

if (description)
{
  script_id(90651);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/22 15:34:21 $");

  script_xref(name:"FEDORA", value:"2016-73c0897e5e");

  script_name(english:"Fedora 24 : webkitgtk4-2.12.1-1.fc24 (2016-73c0897e5e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Highlights in 2.12.0: * Enable FTL by default in JavaScriptCore for
x86_64. * Network process is now used unconditionally. The shared
secondary process model is now the same as using the multiple process
model and setting a process limit of 1. * Switch to use overlay
scrollbars like all other GTK+ widgets and ensure the behavior is
consistent with GTK+ too. * Support for windowless NPAPI plugins with
no UI in non X11 platforms. * Enable GSS-Negotiate support when
available in libsoup. * Improved general performance by better
handling glib main loop sources. * New API to save and restore a
WebView session. Highlights in 2.12.1: * Fix spotify player. * Improve
themed control elements rendering to better match GTK+ widgets. * Make
remote web inspector work again. * Fix several crashes and rendering
issues. * Fix several memory leaks. * Fix the build in Linux /
PowerPC. * Fix detection of S390X and PPC64 architectures. * Fix the
build in glibc-based BSD systems * Translation updates: Brazilian
Portuguese.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/182819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05cf7b62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk4 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC24", reference:"webkitgtk4-2.12.1-1.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4");
}
