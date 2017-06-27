#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-ae1fde5fb8.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99415);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5189", "CVE-2016-5199", "CVE-2016-5201", "CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5210", "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-9650", "CVE-2016-9651");
  script_xref(name:"FEDORA", value:"2017-ae1fde5fb8");

  script_name(english:"Fedora 25 : qt5-qtwebengine (2017-ae1fde5fb8)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates QtWebEngine to the 5.8.0 release. QtWebEngine
5.8.0 is part of the Qt 5.8.0 release, but only the QtWebEngine
component is included in this update.

The update fixes the following security issues in QtWebEngine 5.7.1:
CVE-2016-5182, CVE-2016-5183, CVE-2016-5189, CVE-2016-5199,
CVE-2016-5201, CVE-2016-5203, CVE-2016-5204, CVE-2016-5205,
CVE-2016-5206, CVE-2016-5208, CVE-2016-5207, CVE-2016-5210,
CVE-2016-5211, CVE-2016-5212, CVE-2016-5213, CVE-2016-5214,
CVE-2016-5215. CVE-2016-5216, CVE-2016-5217, CVE-2016-5218,
CVE-2016-5219, CVE-2016-5221, CVE-2016-5222, CVE-2016-5223,
CVE-2016-5224, CVE-2016-5225, CVE-2016-9650 and CVE-2016-9651.

Other immediately usable changes in QtWebEngine 5.8 include :

  - Based on Chromium 53.0.2785.148 with security fixes from
    Chromium up to version 55.0.2883.75. (5.7.1 was based on
    Chromium 49.0.2623.111 with security fixes from Chromium
    up to version 54.0.2840.87.)

  - The `view-source:` scheme is now supported.

  - User scripts now support metadata (`@include`,
    `@exclude`, `@match`) as in Greasemonkey.

  - Some `chrome:` schemes now supported, for instance
    `chrome://gpu`.

  - Several bugs were fixed, see
    https://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/cha
    nges-5.8.0 for details.

The following changes in QtWebEngine 5.8 require compile-time
application support and will only be available after applications are
rebuilt (and patched to remove the checks for Qt 5.8, because Qt is
still version 5.7.1, only QtWebEngine is being updated) :

  - Spellchecking with a forked version of Hunspell. This
    Fedora package automatically converts system Hunspell
    dictionaries (installed by system RPMs into the
    systemwide location) to the Chromium `bdic` format used
    by QtWebEngine (using an RPM file trigger). If you wish
    to use dictionaries installed manually, use the included
    `qwebengine_convert_dict` tool. Alternatively, you can
    also download dictionaries directly in the Chromium
    `bdic` format.

  - Support for printing directly to a printer. (Note that
    QupZilla already supports printing to a printer, because
    it can use the printToPdf API that has existed since
    QtWebEngine 5.7 to print to a printer with the help of
    the `lpr` command-line tool. But other applications such
    as KMail require the new direct printing API.)

  - Added a setting to enable printing of CSS backgrounds.

The following new QML APIs are available to developers :

  - Tooltips (HTML5 global title attribute) are now also
    supported in the QML API.

  - Qt WebEngine (QML) allows defining custom dialogs /
    context menus.

  - Qt WebEngine (QML) on `eglfs` uses builtin dialogs based
    on Qt Quick Controls 2.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-ae1fde5fb8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/changes-5.8.0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qt5-qtwebengine package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"qt5-qtwebengine-5.8.0-8.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
