#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9397.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40990);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/11 13:16:07 $");

  script_cve_id("CVE-2009-2702");
  script_bugtraq_id(36229);
  script_xref(name:"FEDORA", value:"2009-9397");

  script_name(english:"Fedora 11 : akonadi-1.2.1-1.fc11 / kde-l10n-4.3.1-2.fc11 / kdeaccessibility-4.3.1-1.fc11 / etc (2009-9397)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates KDE to 4.3.1, the latest upstream bugfix release. The
main improvements are: * KDE 4.3 is now also available in Croatian. *
A crash when editing toolbar setup has been fixed. * Support for
transferring files through SSH using KIO::Fish has been fixed. * A
number of bugs in KWin, KDE's window and compositing manager has been
fixed. * A large number of bugs in KMail, KDE's email client are now
gone. See http://kde.org/announcements/announce-4.3.1.php for more
information. In addition, this update: * fixes a potential security
issue (CVE-2009-2702) with certificate validation in the KIO KSSL
code. It is believed that the affected code is not actually used (the
code in Qt, for which a security update was already issued, is) and
thus the issue is only potential, but KSSL is being patched just in
case, * splits PolicyKit-kde out of kdebase-workspace again to avoid
forcing it onto GNOME-based setups, where PolicyKit-gnome is desired
instead (#519654).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.3.1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=520661"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13acfbdd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82e4bfc7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5278128c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?962f98d1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?806f73e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e30b566"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?695a1178"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dc47c3c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7ad3e31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad0ea05a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ce3be09"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7703de3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70d44980"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4937f018"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa76debe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b702a69"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?393bda9d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d5f15fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57046329"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33df8c51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b16177e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68bf4020"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f0f09ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ca49022"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:akonadi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeplasma-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC11", reference:"akonadi-1.2.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kde-l10n-4.3.1-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeaccessibility-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeadmin-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeartwork-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-4.3.1-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-runtime-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-workspace-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebindings-4.3.1-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeedu-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdegames-4.3.1-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdegraphics-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdelibs-4.3.1-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdelibs-experimental-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdemultimedia-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdenetwork-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-runtime-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepimlibs-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeplasma-addons-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdesdk-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdetoys-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeutils-4.3.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"oxygen-icon-theme-4.3.1-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "akonadi / kde-l10n / kdeaccessibility / kdeadmin / kdeartwork / etc");
}
