#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-821.
#

include("compat.inc");

if (description)
{
  script_id(19723);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_xref(name:"FEDORA", value:"2005-821");

  script_name(english:"Fedora Core 3 : kernel-2.6.12-1.1376_FC3 (2005-821)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Aug 26 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1376_FC3]

    - Better identify local builds. (#159696)

    - Fix disk/net dump & netconsole. (#152586)

    - Fix up sleeping in invalid context in sym2 driver.
      (#164995)

    - Fix 'semaphore is not ready' error in snd-intel8x0m.

    - Restore hwclock functionality on some systems.
      (#144894)

    - Merge patches proposed for 2.6.12.6

    - Fix typo in ALPS driver.

    - Fix 'No sense' error with Transcend USB key. (#162559)

    - Fix up ide-scsi check for medium not present.
      (#160868)

    - powernow-k8 driver update from 2.6.13rc7

  - Tue Aug 23 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1375_FC3]

    - Work around AMD x86-64 errata 122.

  - Thu Aug 18 2005 David Woodhouse <dwmw2 at redhat.com>

    - Don't probe 8250 ports on ppc32 unless they're in the
      device tree

    - Enable ISDN, 8250 console, i8042 keyboard controller
      on ppc32

    - Audit updates from git tree

  - Tue Aug 16 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1374_FC3]

    - Restrict ipsec socket policy loading to CAP_NET_ADMIN.
      (CVE-2005-2555)

  - Mon Aug 15 2005 Dave Jones <davej at redhat.com>

    - 2.6.11.5

    - Fix module_verify_elf check that rejected valid .ko
      files. (#165528)

  - Thu Aug 11 2005 Dave Jones <davej at redhat.com>

    - Audit speedup in syscall path.

    - Update to a newer ACPI drop.

  - Wed Aug 10 2005 Dave Jones <davej at redhat.com>

    - Reenable 586-smp builds. (Another FC4 change that
      crept in).

  - Fri Aug 5 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1373_FC3]

    - Sync with FC4 update.

    - Add Appletouch support.

    - Audit updates. In particular, don't printk audit
      messages that are passed from userspace when auditing
      is disabled.

  - update to final 2.6.12.4 patchset.

    - ACPI update to 20050729.

    - Disable experimental ACPI HOTKEY driver. (#163355)

  - Thu Aug 4 2005 Dave Jones <davej at redhat.com>

    - Enable Amiga partition support. (#149802)

  - Wed Aug 3 2005 Dave Jones <davej at redhat.com>

    - Silence some messages from PowerMac thermal driver.
      (#158739)

    - nfs server intermitently claimed ENOENT on existing
      files or directories. (#150759)

    - Stop usbhid driver incorrectly claiming Wireless
      Security Lock as a mouse. (#147479)

[plus 8 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-August/001310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8c26923"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"kernel-2.6.12-1.1376_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-debuginfo-2.6.12-1.1376_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-doc-2.6.12-1.1376_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-smp-2.6.12-1.1376_FC3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-doc / kernel-smp");
}
