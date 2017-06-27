#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0963.
#

include("compat.inc");

if (description)
{
  script_id(30084);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:04 $");

  script_cve_id("CVE-2008-0008");
  script_xref(name:"FEDORA", value:"2008-0963");

  script_name(english:"Fedora 8 : pulseaudio-0.9.8-5.fc8 (2008-0963)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jan 23 2008 Lubomir Kundrak <lkundrak at redhat.com>
    0.9.8-5

    - Fix CVE-2008-0008 security issue (#425481)

    - Sun Jan 13 2008 Lubomir Kundrak <lkundrak at
      redhat.com> 0.9.8-4.1

    - Actually add content to
      pulseaudio-0.9.8-create-dot-pulse.patch

    - Make the Source0 tag point to URL instead of a local
      file

    - Drop the nochown patch; it's not applied at all and no
      longer needed

    - Thu Nov 29 2007 Lennart Poettering <lpoetter at
      redhat.com> 0.9.8-4

    - add missing dependency on pulseaudio-utils for
      pulseaudio-module-x11

    - Thu Nov 29 2007 Lennart Poettering <lpoetter at
      redhat.com> 0.9.8-3

    - Create ~/.pulse/ if non-existent

    - Thu Nov 29 2007 Lennart Poettering <lpoetter at
      redhat.com> 0.9.8-2

    - Add missing dependency on
      jack-audio-connection-kit-devel

    - Wed Nov 28 2007 Lennart Poettering <lpoetter at
      redhat.com> 0.9.8-1

    - Upgrade to current upstream

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=425481"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-January/007205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3872f747"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-core-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-libs-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-libs-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"pulseaudio-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-core-libs-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-debuginfo-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-esound-compat-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-libs-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-libs-devel-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-libs-glib2-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-libs-zeroconf-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-bluetooth-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-gconf-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-jack-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-lirc-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-x11-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-module-zeroconf-0.9.8-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pulseaudio-utils-0.9.8-5.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pulseaudio / pulseaudio-core-libs / pulseaudio-debuginfo / etc");
}
