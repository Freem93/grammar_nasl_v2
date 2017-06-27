#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2003-026.
#

include("compat.inc");

if (description)
{
  script_id(13665);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"FEDORA", value:"2003-026");

  script_name(english:"Fedora Core 1 : kernel-2.4.22-1.2129.nptl (2003-026)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The kernel shipped with Fedora Core 1 was vulnerable to a bug in the
error return on a concurrent fork() with threaded exit() which could
be exploited by a user level program to crash the kernel.

In addition to this bug fix, the changelog below details various other
non-security fixes that have been added.

  - Mon Dec 01 2003 Dave Jones <davej at redhat.com>

  - sys_tgkill wasn't enabled on IA32.

  - Sun Nov 30 2003 Dave Jones <davej at redhat.com>

  - Process scheduler fix. When doing sync wakeups we must
    not skip the notification of other cpus if the task is
    not on this runqueue.

  - Wed Nov 26 2003 Justin M. Forbes <64bit_fedora at
    comcast.net>

  - Merge required ia32 syscalls for AMD64

    - [f]truncate64 for 32bit code fix

  - Mon Nov 24 2003 Dave Jones <davej at redhat.com>

  - Fix power-off on shutdown with ACPI.

    - Add missing part of recent cmpci fix

    - Drop CONFIG_NR_CPUS patch which was problematic.

    - Fold futex-fix into main futex patch.

    - Fix TG3 tqueue initialisation.

    - Various NPTL fixes.

  - Fri Nov 14 2003 Dave Jones <davej at redhat.com>

  - Drop netfilter change which proved to be bad upstream.

  - Thu Nov 13 2003 Justin M. Forbes <64bit_fedora at
    comcast.net>

  - Fix NForce3 DMA and ATA133 on AMD64

  - Wed Nov 12 2003 Dave Jones <davej at redhat.com>

  - Fix syscall definitions on AMD64

  - Tue Nov 11 2003 Dave Jones <davej at redhat.com>

  - Fix Intel 440GX Interrupt routing.

    - Fix waitqueue leak in cmpci driver.

  - Mon Nov 10 2003 Dave Jones <davej at redhat.com>

  - Kill noisy warnings in the DRM modules.

    - Merge munged upstream x86-64.org patch for various
      AMD64 fixes.

  - Mon Nov 03 2003 Dave Jones <davej at redhat.com>

  - Further cleanups related to AMD64 build.

  - Fri Oct 31 2003 Dave Jones <davej at redhat.com>

  - Make AMD64 build.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2003-December/000013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6c85103"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-2.4.22-1.2129.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-BOOT-2.4.22-1.2129.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-debuginfo-2.4.22-1.2129.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-doc-2.4.22-1.2129.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-smp-2.4.22-1.2129.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-source-2.4.22-1.2129.nptl")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debuginfo / kernel-doc / kernel-smp / etc");
}
