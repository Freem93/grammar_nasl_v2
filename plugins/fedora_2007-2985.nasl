#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2985.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(28186);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/21 21:54:56 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_xref(name:"FEDORA", value:"2007-2985");

  script_name(english:"Fedora 7 : arts-1.5.8-4.fc7 / kde-i18n-3.5.8-1.fc7 / kdeaccessibility-3.5.8-2.fc7 / etc (2007-2985)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to the latest kde-3.5.8 release. For more details,
see http://kde.org/announcements/announce-3.5.8.php

This also addresses a security issue in kpdf, that can cause crashes
or possibly execute arbitrary code, see
http://www.kde.org/info/security/advisory-20071107-1.txt

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-3.5.8.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20071107-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=352391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=372561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=377321"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b699539c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7060a11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57dc5f3b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a98cbb18"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?008bed9b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a37e498"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7427351b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fa18fb4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f52c292"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9c36eff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c643cc54"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0dd4f079"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eebe18f4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80d7fb2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e0bb518"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd86046e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0a52e83"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a565149"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26de0f7e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68e900ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:arts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:arts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Arabic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Bengali");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Brazil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-British");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Bulgarian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Catalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Chinese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Chinese-Big5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Czech");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Danish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Dutch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Estonian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Finnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-French");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-German");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Greek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Hebrew");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Hindi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Hungarian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Icelandic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Italian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Japanese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Korean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Lithuanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Norwegian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Norwegian-Nynorsk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Polish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Portuguese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Punjabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Romanian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Russian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Serbian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Slovak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Slovenian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Spanish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Swedish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Tamil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Turkish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-i18n-Ukrainian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaddons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaddons-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork-kxs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings-dcopperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdevelop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdevelop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdevelop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdewebdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdewebdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdewebdev-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"arts-1.5.8-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"arts-debuginfo-1.5.8-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"arts-devel-1.5.8-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Arabic-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Bengali-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Brazil-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-British-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Bulgarian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Catalan-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Chinese-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Chinese-Big5-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Czech-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Danish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Dutch-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Estonian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Finnish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-French-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-German-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Greek-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Hebrew-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Hindi-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Hungarian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Icelandic-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Italian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Japanese-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Korean-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Lithuanian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Norwegian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Norwegian-Nynorsk-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Polish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Portuguese-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Punjabi-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Romanian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Russian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Serbian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Slovak-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Slovenian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Spanish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Swedish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Tamil-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Turkish-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kde-i18n-Ukrainian-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeaccessibility-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeaccessibility-debuginfo-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeaddons-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeaddons-debuginfo-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeaddons-extras-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeadmin-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeadmin-debuginfo-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeartwork-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeartwork-debuginfo-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeartwork-extras-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeartwork-icons-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeartwork-kxs-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-debuginfo-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-devel-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-extras-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebindings-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebindings-dcopperl-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebindings-debuginfo-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebindings-devel-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeedu-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeedu-debuginfo-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeedu-devel-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegames-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegames-debuginfo-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegames-devel-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegraphics-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegraphics-debuginfo-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegraphics-devel-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdegraphics-extras-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdelibs-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdelibs-apidocs-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdelibs-debuginfo-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdelibs-devel-3.5.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdemultimedia-3.5.8-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdemultimedia-debuginfo-3.5.8-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdemultimedia-devel-3.5.8-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdemultimedia-extras-3.5.8-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdenetwork-3.5.8-6.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdenetwork-debuginfo-3.5.8-6.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdenetwork-devel-3.5.8-6.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdenetwork-extras-3.5.8-6.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdepim-3.5.8-5.svn20071013.ent.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdepim-debuginfo-3.5.8-5.svn20071013.ent.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdepim-devel-3.5.8-5.svn20071013.ent.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdesdk-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdesdk-debuginfo-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdesdk-devel-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdetoys-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdetoys-debuginfo-3.5.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeutils-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeutils-debuginfo-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeutils-devel-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdeutils-extras-3.5.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdevelop-3.5.0-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdevelop-debuginfo-3.5.0-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdevelop-devel-3.5.0-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdewebdev-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdewebdev-debuginfo-3.5.8-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdewebdev-devel-3.5.8-3.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arts / arts-debuginfo / arts-devel / kde-i18n-Arabic / etc");
}
