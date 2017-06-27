#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-6096.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47415);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_cve_id("CVE-2010-0436");
  script_xref(name:"FEDORA", value:"2010-6096");

  script_name(english:"Fedora 12 : PyQt4-4.7.2-2.fc12 / kdeaccessibility-4.4.2-1.fc12 / kdeadmin-4.4.2-1.fc12 / etc (2010-6096)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0431e1eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d55febc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5dfb548"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eebcedda"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10748849"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aed47264"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1af760fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dc0fbc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?414121cf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1daf72ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cb98039"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039472.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b54c2ba8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cb58e4e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0322fb3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c55988d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1857ae5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f09befd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d05bf80"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3aade582"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?588c05fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23520fc6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a729217d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd2eda3c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/039484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acb5306e"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"PyQt4-4.7.2-2.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeaccessibility-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeadmin-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeartwork-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdebase-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdebase-runtime-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdebase-workspace-4.4.2-5.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdebindings-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeedu-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdegames-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdegraphics-4.4.2-3.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdelibs-4.4.2-2.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdemultimedia-4.4.2-2.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdenetwork-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdepim-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdepim-runtime-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdepimlibs-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeplasma-addons-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdesdk-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdetoys-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"kdeutils-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"konq-plugins-4.4.0-3.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"oxygen-icon-theme-4.4.2-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"sip-4.10.1-2.fc12")) flag++;


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
