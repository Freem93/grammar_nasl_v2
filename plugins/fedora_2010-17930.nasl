#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17930.
#

include("compat.inc");

if (description)
{
  script_id(50814);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:38:15 $");

  script_cve_id("CVE-2010-4176");
  script_osvdb_id(69466);
  script_xref(name:"FEDORA", value:"2010-17930");

  script_name(english:"Fedora 14 : dracut-006-5.fc14 / udev-161-7.fc14 (2010-17930)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that /dev/systty device file created by
dracut-generated initramfs scripts used an insecure file permissions.
This could possibly allow local user to snoop on other user's
terminal.

Updated dracut no longer creates this file as device file, rather
creates it a symbolic link to tty0 device file. However, for this
change to take effect, user needs to re-generate initramfs (any
initramfs for all kernels that are going to be booted in the future)
using updated dracut version and reboot the system.

This update also provides updated udev packages that replace systty
device file with a symlink on udev package upgrade and each udev
start. This provides a work-around fix for users that fail to
regenerate their initramfs and reboot as described above.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=654489"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e0c261a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15a3afa2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dracut and / or udev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/28");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"dracut-006-5.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"udev-161-7.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / udev");
}
