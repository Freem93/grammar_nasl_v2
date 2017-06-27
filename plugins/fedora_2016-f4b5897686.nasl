#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-f4b5897686.
#

include("compat.inc");

if (description)
{
  script_id(94125);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/19 14:37:27 $");

  script_xref(name:"FEDORA", value:"2016-f4b5897686");

  script_name(english:"Fedora 24 : 1:epiphany / webkitgtk4 (2016-f4b5897686)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update WebKitGTK+ package to 2.14.1. Major changes in 2.14.0 :

  - Threaded compositor is enabled by default in both X11
    and Wayland.

  - Accelerated compositing is now supported in Wayland.

  - Clipboard works in Wayland too.

  - Memory pressure handler always works even when cgroups
    is not present or not configured.

  - The HTTP disk cache implements speculative revalidation
    of resources.

  - DRI3 is no longer a problem when using the modesetting
    intel driver.

  - The amount of file descriptors that are kept open has
    been drastically reduced.

Fixes from 2.14.1 :

  - MiniBrowser and jsc binaries are now installed in
    pkglibexecdir instead of bindir.

  - Improve performance when resizing a window with multiple
    web views in X11.

  - Check whether GDK can use GL before using
    gdk_cairo_draw_from_gl() in Wayland.

  - Updated default UserAgent string or better
    compatibility.

  - Fix a crash on github.com in
    IntlDateTimeFormat::resolvedOptions when using the C
    locale.

  - Fix BadDamage X errors when closing the web view in X11.

  - Fix UIProcess crash when using Japanese input method.

  - Fix build with clang due to missing header includes.

  - Fix the build with USE_REDIRECTED_XCOMPOSITE_WINDOW
    disabled.

  - Fix several crashes and rendering issues.

  - Translation updates: German.

Update Epiphany to be compatible with the new WebKitGTK+ package.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-f4b5897686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:epiphany and / or webkitgtk4 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"epiphany-3.20.4-1.fc24", epoch:"1")) flag++;
if (rpm_check(release:"FC24", reference:"webkitgtk4-2.14.1-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:epiphany / webkitgtk4");
}
