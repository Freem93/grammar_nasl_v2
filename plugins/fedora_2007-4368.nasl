#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4368.
#

include("compat.inc");

if (description)
{
  script_id(29710);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-4368");

  script_name(english:"Fedora 8 : Terminal-0.2.8-2.fc8 / Thunar-0.9.0-2.fc8 / exo-0.3.4-1.fc8 / gtk-xfce-engine-2.4.2-1.fc8 / etc (2007-4368)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xfce 4.4.2 update.

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
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006014.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e7ece56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?618a9895"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48e47ccd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab765a90"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a475efd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b61919fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8e1c93a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e28a4a47"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006022.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?697134cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d98327fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad37a290"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?037349ba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3f0ff1d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e64b45d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006028.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c77ab10"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fe15e52"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d5d1e83"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8689ddd9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?744c244e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e673ccc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40cb2f1a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?376fae98"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?585a36ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14fd6dde"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31f1bbaf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11d49233"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97c20d94"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b38fdef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11a2f4c5"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"Terminal-0.2.8-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"Terminal-debuginfo-0.2.8-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"Thunar-0.9.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"Thunar-debuginfo-0.9.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"Thunar-devel-0.9.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"exo-0.3.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"exo-debuginfo-0.3.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"exo-devel-0.3.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtk-xfce-engine-2.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtk-xfce-engine-debuginfo-2.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4mcs-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4mcs-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4mcs-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4util-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4util-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfce4util-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfcegui4-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfcegui4-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libxfcegui4-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"mousepad-0.2.13-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"mousepad-debuginfo-0.2.13-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"orage-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"orage-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"python-exo-0.3.4-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"thunar-volman-0.2.0-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"thunar-volman-debuginfo-0.2.0-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-mcs-manager-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-mcs-manager-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-mcs-manager-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-mcs-plugins-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-mcs-plugins-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-utils-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce-utils-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-appfinder-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-appfinder-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-cpugraph-plugin-0.4.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-cpugraph-plugin-debuginfo-0.4.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-fsguard-plugin-0.4.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-fsguard-plugin-debuginfo-0.4.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-icon-theme-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-mixer-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-mixer-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-modemlights-plugin-0.1.3.99-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-modemlights-plugin-debuginfo-0.1.3.99-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-notes-plugin-1.6.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-notes-plugin-debuginfo-1.6.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-panel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-panel-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-panel-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-places-plugin-1.0.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-places-plugin-debuginfo-1.0.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-sensors-plugin-0.10.99.2-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-sensors-plugin-debuginfo-0.10.99.2-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-session-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-session-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-session-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-session-engines-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-weather-plugin-0.6.2-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfce4-weather-plugin-debuginfo-0.6.2-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfdesktop-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfdesktop-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfprint-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfprint-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfprint-devel-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfwm4-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfwm4-debuginfo-4.4.2-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"xfwm4-themes-4.4.2-1.fc8")) flag++;


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
