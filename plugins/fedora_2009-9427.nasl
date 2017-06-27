#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9427.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40991);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/11 13:16:07 $");

  script_cve_id("CVE-2009-2702");
  script_bugtraq_id(36229);
  script_xref(name:"FEDORA", value:"2009-9427");

  script_name(english:"Fedora 10 : akonadi-1.2.1-1.fc10 / kde-l10n-4.3.1-2.fc10 / kdeaccessibility-4.3.1-1.fc10 / etc (2009-9427)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8baf285b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02a364ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cfd1e4c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f26f431"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e22e4ae6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7ac678d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5f6c279"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75a3da3e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23d3fcca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1094d10d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?626f85ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50355638"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb89b098"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb4b0613"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?470f2522"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0b1c795"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?288efabf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?989bdcf8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82b6d740"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fb80d49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e20147cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f56379e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?072c78c7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3460a6d"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"akonadi-1.2.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kde-l10n-4.3.1-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeaccessibility-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeadmin-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeartwork-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdebase-4.3.1-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdebase-runtime-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdebase-workspace-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdebindings-4.3.1-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeedu-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdegames-4.3.1-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdegraphics-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdelibs-4.3.1-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdelibs-experimental-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdemultimedia-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdenetwork-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdepim-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdepim-runtime-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdepimlibs-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeplasma-addons-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdesdk-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdetoys-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kdeutils-4.3.1-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"oxygen-icon-theme-4.3.1-1.fc10")) flag++;


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
