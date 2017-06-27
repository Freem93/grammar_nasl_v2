#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-9886.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84312);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:22:35 $");

  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3150", "CVE-2015-3151", "CVE-2015-3159", "CVE-2015-3315");
  script_xref(name:"FEDORA", value:"2015-9886");

  script_name(english:"Fedora 22 : abrt-2.6.0-1.fc22 / gnome-abrt-1.2.0-1.fc22 / libreport-2.6.0-1.fc22 / satyr-0.18-1.fc22 (2015-9886)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes for :

  - CVE-2015-3315

    - CVE-2015-3142

    - CVE-2015-1869

    - CVE-2015-1870

    - CVE-2015-3151

    - CVE-2015-3150

    - CVE-2015-3159

abrt :

  - Move the default dump location from /var/tmp/abrt to
    /var/spool/abrt

    - Use root for owner of all dump directories

    - Stop reading hs_error.log from /tmp

    - Don not save the system logs by default

    - Don not save dmesg if kernel.dmesg_restrict=1

libreport :

  - Harden the code against directory traversal, symbolic
    and hard link attacks

    - Fix a bug causing that the first value of
      AlwaysExcludedElements was ignored

    - Fix missing icon for the 'Stop' button icon name

    - Improve development documentation

    - Translations updates

gnome-abrt :

  - Enabled the Details also for the System problems

    - Do not crash in the testing of availabitlity of
      XServer

    - Fix 'Open problem's data directory'

    - Quit Application on Ctrl+Q

    - Translation updates

satyr :

  - New kernel taint flags

    - More secure core stacktraces from core hook

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1128400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1212821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1212865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1212871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1214452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1214609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1216975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1218239"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160568.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c64f5b7d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160569.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b84b95df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b449c29f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca41820c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:satyr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"abrt-2.6.0-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"gnome-abrt-1.2.0-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"libreport-2.6.0-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"satyr-0.18-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / gnome-abrt / libreport / satyr");
}
