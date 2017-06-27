#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-5221.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53520);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_cve_id("CVE-2011-1168");
  script_bugtraq_id(47304);
  script_xref(name:"FEDORA", value:"2011-5221");

  script_name(english:"Fedora 15 : kde-l10n-4.6.2-1.fc15.1 / kdeaccessibility-4.6.2-1.fc15 / kdeadmin-4.6.2-2.fc15 / etc (2011-5221)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update is the second in a series of monthly stabilization updates
to the 4.6 series. 4.6.2 brings many bugfixes and translation updates
on top of the latest edition in the 4.6 series and is a recommended
update for everyone running 4.6.1 or earlier versions. See also:
http://kde.org/announcements/announce-4.6.2.php

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.6.2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=695398"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64727e05"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34961c79"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d50cdd0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b876a992"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8c6ac2b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?420a19f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2045445e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe65a561"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9102980b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058599.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24e4ba54"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8db9e8d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e47e477f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?902e3561"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a53d59de"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bb1dfe2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd01af66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?264fe26b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058607.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec5cb4a0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?486d2f8c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058609.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65e4f831"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeplasma-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"kde-l10n-4.6.2-1.fc15.1")) flag++;
if (rpm_check(release:"FC15", reference:"kdeaccessibility-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdeadmin-4.6.2-2.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdeartwork-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdebase-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdebase-runtime-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdebase-workspace-4.6.2-2.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdebindings-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdeedu-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdegames-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdegraphics-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdelibs-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdemultimedia-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdenetwork-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdepimlibs-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdeplasma-addons-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdesdk-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdetoys-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"kdeutils-4.6.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"oxygen-icon-theme-4.6.2-1.fc15")) flag++;


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
