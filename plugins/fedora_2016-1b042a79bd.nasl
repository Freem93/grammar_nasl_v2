#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-1b042a79bd.
#

include("compat.inc");

if (description)
{
  script_id(94413);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/03 14:55:08 $");

  script_cve_id("CVE-2016-7966", "CVE-2016-7967", "CVE-2016-7968");
  script_xref(name:"FEDORA", value:"2016-1b042a79bd");

  script_name(english:"Fedora 24 : 1:kdepim-runtime / 7:kdepim / kdepim-addons / kdepim-apps-libs / etc (2016-1b042a79bd)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE PIM Applications 16.08.2,
https://www.kde.org/announcements/announce-applications-16.08.2.php

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-1b042a79bd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/announcements/announce-applications-16.08.2.php"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:kdepim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:7:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-apps-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-contacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-notes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-calendarsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-eventviews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-gpgmepp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-grantleetheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-incidenceeditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kalarmcal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcalendarcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcalendarutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kcontacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kdgantt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kholidays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kidentitymanagement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kimap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kmailtransport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kmbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kmime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kontactinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kpimtextedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-libgravatar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-libkdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-libkleo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-libksieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-mailcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-mailimporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-messagelib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-pimcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-syndication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kleopatra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC24", reference:"kdepim-runtime-16.08.2-1.fc24", epoch:"1")) flag++;
if (rpm_check(release:"FC24", reference:"kdepim-16.08.2-1.fc24", epoch:"7")) flag++;
if (rpm_check(release:"FC24", reference:"kdepim-addons-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kdepim-apps-libs-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-calendar-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-contacts-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-mime-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-notes-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-search-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-akonadi-server-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-calendarsupport-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-eventviews-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-gpgmepp-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-grantleetheme-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-incidenceeditor-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kalarmcal-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kblog-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcalendarcore-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcalendarutils-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kcontacts-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kdgantt2-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kholidays-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kidentitymanagement-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kimap-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kldap-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kmailtransport-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kmbox-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kmime-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kontactinterface-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-kpimtextedit-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-ktnef-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-libgravatar-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-libkdepim-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-libkleo-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-libksieve-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-mailcommon-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-mailimporter-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-messagelib-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-pimcommon-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kf5-syndication-16.08.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"kleopatra-16.08.2-1.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:kdepim-runtime / 7:kdepim / kdepim-addons / kdepim-apps-libs / etc");
}
