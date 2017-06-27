#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-8577.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47504);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-1000", "CVE-2010-1511");
  script_xref(name:"FEDORA", value:"2010-8577");

  script_name(english:"Fedora 13 : kde-l10n-4.4.3-1.fc13 / kdeaccessibility-4.4.3-1.fc13.1 / kdeadmin-4.4.3-1.fc13.1 / etc (2010-8577)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041937.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a468408"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041938.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbfc27d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041939.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a13ec52"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?900ddc4c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041941.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2a8cc5b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041942.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c80fb56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3eb2b768"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4b7b040"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041945.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c4e3e3a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88d2ec93"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4e005ff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?211d3752"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?224defa7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48bec674"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16d4c246"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfea3628"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f373e21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93c7b12c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab4b7bab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c81037c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0adfeba3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06b429d7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"kde-l10n-4.4.3-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"kdeaccessibility-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdeadmin-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdeartwork-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdebase-4.4.3-2.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdebase-runtime-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdebase-workspace-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdebindings-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdeedu-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdegames-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdegraphics-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdelibs-4.4.3-2.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"kdemultimedia-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdenetwork-4.4.3-3.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"kdepim-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdepim-runtime-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdepimlibs-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdeplasma-addons-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdesdk-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdetoys-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"kdeutils-4.4.3-1.fc13.1")) flag++;
if (rpm_check(release:"FC13", reference:"oxygen-icon-theme-4.4.3-1.fc13")) flag++;


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
