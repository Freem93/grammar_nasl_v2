#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-8183.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76845);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:40:33 $");

  script_cve_id("CVE-2014-3970");
  script_bugtraq_id(67814);
  script_xref(name:"FEDORA", value:"2014-8183");

  script_name(english:"Fedora 20 : qt-mobility-1.2.2-0.16.20140317git169da60c.fc20 / audacious-plugins-3.4.3-2.fc20 / etc (2014-8183)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Rebase current post-4.0 snapshot to 5.0 release, see also:
http://www.freedesktop.org/wiki/Software/PulseAudio/Notes/5.0/

This update restores compatibility with pulseaudio upstream ABI, and
includes rebuilds of affected fedora packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.freedesktop.org/wiki/Software/PulseAudio/Notes/5.0/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1104835"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db3dbc4c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4edc21b4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10339856"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1de70ea7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2809bde4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5bb07a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?627fbac2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?068cff1e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135995.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e639da3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a489f5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ba1125"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?955bcc9e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dd424db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?741a29af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53c6f133"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca0a037e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16e511e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cd431f7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a4de7b6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29726d6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5292a06"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04a9efb1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bf1d4e8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18a640bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2126f1d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7953bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f83d50"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136014.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1f9d054"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d691c341"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8b537e8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0922891"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:audacious-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cinnamon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cinnamon-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cinnamon-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:empathy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ffgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fldigi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gqrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacamole-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libmikmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:minimodem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mumble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:paprefs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phonon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qmmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-mobility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sidplayfp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:speech-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sphinxtrain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"audacious-plugins-3.4.3-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"cinnamon-2.2.14-5.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"cinnamon-control-center-2.2.10-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"cinnamon-settings-daemon-2.2.4-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"control-center-3.10.3-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"empathy-3.10.3-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ffgtk-0.8.6-7.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"fldigi-3.21.83-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"fluidsynth-1.1.6-4.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"gnome-settings-daemon-3.10.3-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"gnome-shell-3.10.4-7.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"gqrx-2.2.0-6.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"gstreamer1-plugins-good-1.2.4-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"guacamole-server-0.8.4-3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libmikmod-3.3.6-3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"minimodem-0.19-3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"mumble-1.2.6-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"paprefs-0.9.10-7.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"phonon-4.7.2-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"pulseaudio-5.0-7.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"qemu-1.6.2-7.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"qmmp-0.7.7-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"qt-4.8.6-9.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"qt-mobility-1.2.2-0.16.20140317git169da60c.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"qt5-qtmultimedia-5.3.1-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"sidplayfp-1.2.0-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"speech-dispatcher-0.8-9.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"sphinxtrain-1.0.8-13.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"spice-gtk-0.23-3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"xmp-4.0.7-2.fc20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audacious-plugins / cinnamon / cinnamon-control-center / etc");
}
