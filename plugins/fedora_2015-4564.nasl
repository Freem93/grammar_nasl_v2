#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-4564.
#

include("compat.inc");

if (description)
{
  script_id(82603);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:06:18 $");

  script_xref(name:"FEDORA", value:"2015-4564");

  script_name(english:"Fedora 21 : mingw-qt5-qtbase-5.4.1-1.fc21 / mingw-qt5-qtdeclarative-5.4.1-1.fc21 / etc (2015-4564)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Qt 5.4.1

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1204798"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fcdaca3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a71f6ac4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6538fe66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154289.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06739c92"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8763ce17"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4beb366b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ea03efb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b77924b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?137ca552"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9068c1bb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49fcb9af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154297.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d07326ec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51773131"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff316056"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtquick1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtwebkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-qt5-qtwinextras");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtbase-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtdeclarative-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtgraphicaleffects-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtimageformats-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtlocation-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtmultimedia-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtquick1-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtscript-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtsensors-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtsvg-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qttools-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qttranslations-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtwebkit-5.4.1-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"mingw-qt5-qtwinextras-5.4.1-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw-qt5-qtbase / mingw-qt5-qtdeclarative / etc");
}
