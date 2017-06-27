#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-8547.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47499);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-0436", "CVE-2010-1000", "CVE-2010-1511");
  script_xref(name:"FEDORA", value:"2010-8547");

  script_name(english:"Fedora 11 : kde-l10n-4.4.3-1.fc11 / kdeaccessibility-4.4.3-1.fc11.1 / kdeadmin-4.4.3-1.fc11.1 / etc (2010-8547)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update set updates the KDE Software Compilation (KDE SC) to KDE
SC 4.4.3, which has a number of improvements: * Numerous fixes in
Konsole, KDE's terminal emulator, among them two possible crashers in
session management * Flash plugin support in KHTML has been enhanced
to work with newest Youtube skins * Case-sensitivity in renaming fixes
in KIO, KDE's network-transparent I/O library

  - Hiding the mouse cursor in some special cases in
    presentation mode and two possible crashers have been
    fixed and more bugfixes and translation updates. See
    http://kde.org/announcements/announce-4.4.3.php for more
    information. In addition, the security issues
    CVE-2010-1000 and CVE-2010-1511 (improper sanitization
    of metalink attribute for downloading files) in KGet
    have been fixed, and Kppp now prompts for the root
    password instead of failing with a cryptic error when
    run as a regular user.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.4.3.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=591631"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041972.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?640f7671"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4b7816c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041974.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?109a9edd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16bd8673"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b1c80f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bdf17ee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4507a9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d6ace0b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40a6a16c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041981.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7532cdf8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde56745"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8aa919f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29befc97"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23bd5d8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041986.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fea11b7d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e46850c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6a0d640"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adba972c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9fe5adf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0da02497"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daf56c91"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ecea954"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (rpm_check(release:"FC11", reference:"kde-l10n-4.4.3-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeaccessibility-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdeadmin-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdeartwork-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-4.4.3-2.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-runtime-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-workspace-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdebindings-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdeedu-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdegames-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdegraphics-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdelibs-4.4.3-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdemultimedia-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdenetwork-4.4.3-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-runtime-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdepimlibs-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdeplasma-addons-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdesdk-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdetoys-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"kdeutils-4.4.3-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"oxygen-icon-theme-4.4.3-1.fc11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-l10n / kdeaccessibility / kdeadmin / kdeartwork / kdebase / etc");
}
