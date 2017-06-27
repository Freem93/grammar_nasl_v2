#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4385.
#

include("compat.inc");

if (description)
{
  script_id(29711);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-4385");

  script_name(english:"Fedora 7 : Terminal-0.2.8-2.fc7 / Thunar-0.9.0-2.fc7 / exo-0.3.4-1.fc7 / gtk-xfce-engine-2.4.2-1.fc7 / etc (2007-4385)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xfce update to 4.4.2.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=382471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=412751"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76b44222"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a086046"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb3514da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b7b3468"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005986.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e811a72"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fee77ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6239b3d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39093a77"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d59d667e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7572e034"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47a2df07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f635467b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5d35af5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005995.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9092f1e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c3ead4a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d0517ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c04f08d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b982503"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38fe2b93"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bf38554"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed9ddde1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcfeddf3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfc65d2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa644144"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79d2a4f8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a607384b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68e2969c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f746bb0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f062e6ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Terminal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Thunar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Thunar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Thunar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:exo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk-xfce-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk-xfce-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4mcs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4mcs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfce4util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfcegui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfcegui4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxfcegui4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mousepad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mousepad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:orage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:orage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-exo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunar-volman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunar-volman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-mcs-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-mcs-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-mcs-manager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-mcs-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-mcs-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-appfinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-appfinder-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-cpugraph-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-cpugraph-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-fsguard-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-fsguard-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-mixer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-mixer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-modemlights-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-modemlights-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-notes-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-notes-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-panel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-panel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-places-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-places-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-sensors-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-sensors-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-session-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-session-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-session-engines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-weather-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfce4-weather-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfdesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfdesktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfprint-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfprint-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfwm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfwm4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfwm4-themes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");
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
if (rpm_check(release:"FC7", reference:"Terminal-0.2.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"Terminal-debuginfo-0.2.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"Thunar-0.9.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"Thunar-debuginfo-0.9.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"Thunar-devel-0.9.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"exo-0.3.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"exo-debuginfo-0.3.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"exo-devel-0.3.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtk-xfce-engine-2.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtk-xfce-engine-debuginfo-2.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4mcs-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4mcs-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4mcs-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4util-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4util-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfce4util-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfcegui4-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfcegui4-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libxfcegui4-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mousepad-0.2.13-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mousepad-debuginfo-0.2.13-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"orage-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"orage-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"python-exo-0.3.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"thunar-volman-0.2.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"thunar-volman-debuginfo-0.2.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-mcs-manager-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-mcs-manager-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-mcs-manager-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-mcs-plugins-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-mcs-plugins-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-utils-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce-utils-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-appfinder-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-appfinder-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-cpugraph-plugin-0.4.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-cpugraph-plugin-debuginfo-0.4.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-fsguard-plugin-0.4.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-fsguard-plugin-debuginfo-0.4.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-icon-theme-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-mixer-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-mixer-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-modemlights-plugin-0.1.3.99-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-modemlights-plugin-debuginfo-0.1.3.99-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-notes-plugin-1.6.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-notes-plugin-debuginfo-1.6.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-panel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-panel-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-panel-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-places-plugin-1.0.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-places-plugin-debuginfo-1.0.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-sensors-plugin-0.10.99.2-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-sensors-plugin-debuginfo-0.10.99.2-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-session-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-session-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-session-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-session-engines-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-weather-plugin-0.6.2-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfce4-weather-plugin-debuginfo-0.6.2-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfdesktop-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfdesktop-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfprint-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfprint-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfprint-devel-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfwm4-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfwm4-debuginfo-4.4.2-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xfwm4-themes-4.4.2-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Terminal / Terminal-debuginfo / Thunar / Thunar-debuginfo / etc");
}
