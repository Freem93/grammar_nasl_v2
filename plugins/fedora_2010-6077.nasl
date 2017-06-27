#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-6077.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47414);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_cve_id("CVE-2010-0436");
  script_xref(name:"FEDORA", value:"2010-6077");

  script_name(english:"Fedora 11 : PyQt4-4.7.2-2.fc11 / kdeaccessibility-4.4.2-1.fc11 / kdeadmin-4.4.2-1.fc11 / etc (2010-6077)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update set updates the KDE Software Compilation (KDE SC) to KDE
SC 4.4.2, which has a number of improvements: * Possible crashes in
Plasma, Dolphin and Okular have been fixed * The Microblog applet now
shows the correct time in the timeline * The audioplayer KRunner
plugin has been fixed to not freeze the KRunner UI anymore and more
bugfixes and translation updates. See
http://kde.org/announcements/announce-4.4.2.php for more information.
* a couple of small powerdevil patches (see kde bugs 221637, 221637),
* upstream kdm security fix for CVE-2010-0436 Also included are the
bugfix releases SIP 4.10.1:
http://www.riverbankcomputing.co.uk/static/Downloads/sip4/ChangeLog
and PyQt4 4.7.2:
http://www.riverbankcomputing.co.uk/static/Downloads/PyQt4/ChangeLog

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.4.2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.riverbankcomputing.co.uk/static/Downloads/PyQt4/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.riverbankcomputing.co.uk/static/Downloads/sip4/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=570613"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039573.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b88457e9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039574.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e89ab479"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?008c8f08"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039576.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f957660"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039577.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?090db632"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039578.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a753ea21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039579.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faea13df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6741f976"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9beb3f37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7c64ff0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5504c16"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f177a37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039585.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cccb070"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bbe5187"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a4fa76"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cad2bb02"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82257abf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc2b2cac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24ed6c38"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2b5bd56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0e2e675"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f65dc4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cae7d34"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f837811c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:PyQt4");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:konq-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
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
if (rpm_check(release:"FC11", reference:"PyQt4-4.7.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeaccessibility-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeadmin-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeartwork-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-runtime-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebase-workspace-4.4.2-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdebindings-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeedu-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdegames-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdegraphics-4.4.2-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdelibs-4.4.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdemultimedia-4.4.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdenetwork-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepim-runtime-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdepimlibs-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeplasma-addons-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdesdk-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdetoys-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kdeutils-4.4.2-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"konq-plugins-4.4.0-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"oxygen-icon-theme-4.4.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"sip-4.10.1-2.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PyQt4 / kdeaccessibility / kdeadmin / kdeartwork / kdebase / etc");
}
