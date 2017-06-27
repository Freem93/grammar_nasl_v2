#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0994.
#

include("compat.inc");

if (description)
{
  script_id(30085);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:04 $");

  script_cve_id("CVE-2008-0008");
  script_xref(name:"FEDORA", value:"2008-0994");

  script_name(english:"Fedora 7 : pulseaudio-0.9.6-2.fc7.1 (2008-0994)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jan 23 2008 Lubomir Kundrak <lkundrak at redhat.com>
    0.9.6-2.1

    - Fix CVE-2008-0008 security issue (#425481)

    - Tue May 29 2007 Pierre Ossman <drzeus at drzeus.cx>
      0.9.6-2

    - Add libatomic_ops-devel as a build requirement.

    - Tue May 29 2007 Pierre Ossman <drzeus at drzeus.cx>
      0.9.6-1

    - Upgrade to 0.9.6.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=425481"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-January/007222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e76b76dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-lib-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-lib-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"pulseaudio-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-debuginfo-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-devel-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-esound-compat-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-lib-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-lib-devel-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-lib-glib2-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-lib-zeroconf-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-module-gconf-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-module-jack-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-module-lirc-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-module-x11-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-module-zeroconf-0.9.6-2.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"pulseaudio-utils-0.9.6-2.fc7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pulseaudio / pulseaudio-debuginfo / pulseaudio-devel / etc");
}
