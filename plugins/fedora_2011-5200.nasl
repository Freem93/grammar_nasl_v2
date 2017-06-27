#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-5200.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53519);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_cve_id("CVE-2011-1168");
  script_bugtraq_id(47304);
  script_xref(name:"FEDORA", value:"2011-5200");

  script_name(english:"Fedora 14 : darktable-0.8-7.fc14.1 / exiv2-0.21.1-1.fc14 / geeqie-1.0-9.fc14.1 / gipfel-0.3.2-7.fc14 / etc (2011-5200)");
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

Also included is a new exiv2-0.21.x release, see:
http://exiv2.org/whatsnew.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://exiv2.org/whatsnew.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.6.2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=695398"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?996554bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04deee3b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b0082a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39774ff5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d88bc0d6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b46347c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?334c8e15"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a9e7265"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b179171e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0153dbae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe90356d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3d6be03"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80430da4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058672.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?931a21f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058673.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d04c9410"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058674.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66abbf55"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?192117a3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058676.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3573b908"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058677.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dab15031"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d107994"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e12449f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97df43a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c008b398"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31692b73"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2509af09"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9092685a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2155c5eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd68d8a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058687.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a77f359d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058688.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?355c594f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57a4bb05"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bd81d0c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058691.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02b21af7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?671b3d96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?640bc83a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058694.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0779f00b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?979b2d11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058696.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa630147"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f003a56a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?024bcd3b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27dd45d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:darktable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:geeqie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gipfel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gpscorrelate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gthumb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:hugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:immix");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kphotoalbum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libextractor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libgexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:merkaartor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pyexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qtpfsgui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rawstudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:shotwell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:strigi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ufraw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"darktable-0.8-7.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"exiv2-0.21.1-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"geeqie-1.0-9.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gipfel-0.3.2-7.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-commander-1.2.8.10-1.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gpscorrelate-1.6.1-3.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"gthumb-2.12.2-1.fc14.2")) flag++;
if (rpm_check(release:"FC14", reference:"hugin-2010.2.0-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"immix-1.3.2-10.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kde-l10n-4.6.2-1.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"kdeaccessibility-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdeadmin-4.6.2-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdeartwork-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdebase-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdebase-runtime-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdebase-workspace-4.6.2-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdebindings-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdeedu-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdegames-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdegraphics-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdelibs-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdemultimedia-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdenetwork-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdepimlibs-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdeplasma-addons-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdesdk-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdetoys-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"kdeutils-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"koffice-2.3.3-1.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"kphotoalbum-4.1.1-8.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"krename-4.0.7-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"libextractor-0.6.2-1402.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"libgexiv2-0.2.2-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"merkaartor-0.17.2-2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"oxygen-icon-theme-4.6.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"pyexiv2-0.3.0-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"qtpfsgui-1.9.3-6.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"rawstudio-2.0-0.1.fc14.beta1.1")) flag++;
if (rpm_check(release:"FC14", reference:"shotwell-0.8.1-3.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"strigi-0.7.2-5.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"ufraw-0.18-2.fc14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "darktable / exiv2 / geeqie / gipfel / gnome-commander / etc");
}
