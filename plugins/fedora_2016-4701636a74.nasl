#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-4701636a74.
#

include("compat.inc");

if (description)
{
  script_id(92530);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/18 16:52:28 $");

  script_cve_id("CVE-2016-6232");
  script_xref(name:"FEDORA", value:"2016-4701636a74");

  script_name(english:"Fedora 24 : 1:oxygen-icon-theme / breeze-icon-theme / extra-cmake-modules / kf5 / etc (2016-4701636a74)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE Frameworks 5.24, see also see also
https://www.kde.org/announcements/kde-frameworks-5.24.0.php

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-4701636a74"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:breeze-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:extra-cmake-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-attica");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-baloo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-bluez-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-frameworkintegration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kactivities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kactivities-stats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kapidox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-karchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kbookmarks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcmutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcodecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcompletion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kconfigwidgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcoreaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcrash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdbusaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdelibs4support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdesignerplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdesu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdewebkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdoctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kemoticons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kfilemetadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kglobalaccel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kguiaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-khtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-ki18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kiconthemes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kidletime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kitemmodels");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kitemviews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kjobwidgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kjsembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kmediaplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-knewstuff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-knotifications");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-knotifyconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kpackage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kparts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kpeople");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kplotting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kpty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kross");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-krunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-ktexteditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-ktextwidgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kunitconversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kwallet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kwidgetsaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kwindowsystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kxmlgui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kxmlrpcclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-modemmanager-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-networkmanager-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-solid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-sonnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-threadweaver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");
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
if (rpm_check(release:"FC24", reference:"oxygen-icon-theme-5.24.0-1.fc24", epoch:"1")) flag++;
if (rpm_check(release:"FC24", reference:"breeze-icon-theme-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"extra-cmake-modules-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-attica-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-baloo-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-bluez-qt-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-frameworkintegration-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kactivities-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kactivities-stats-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kapidox-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-karchive-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kauth-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kbookmarks-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcmutils-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcodecs-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcompletion-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kconfig-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kconfigwidgets-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcoreaddons-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcrash-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdbusaddons-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdeclarative-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kded-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdelibs4support-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdesignerplugin-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdesu-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdewebkit-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdnssd-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdoctools-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kemoticons-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kfilemetadata-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kglobalaccel-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kguiaddons-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-khtml-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-ki18n-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kiconthemes-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kidletime-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kimageformats-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kinit-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kio-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kitemmodels-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kitemviews-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kjobwidgets-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kjs-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kjsembed-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kmediaplayer-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-knewstuff-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-knotifications-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-knotifyconfig-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kpackage-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kparts-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kpeople-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kplotting-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kpty-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kross-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-krunner-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kservice-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-ktexteditor-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-ktextwidgets-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kunitconversion-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kwallet-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kwayland-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kwidgetsaddons-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kwindowsystem-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kxmlgui-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kxmlrpcclient-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-modemmanager-qt-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-networkmanager-qt-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-plasma-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-solid-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-sonnet-5.24.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-threadweaver-5.24.0-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:oxygen-icon-theme / breeze-icon-theme / extra-cmake-modules / kf5 / etc");
}
