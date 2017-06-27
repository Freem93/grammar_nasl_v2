#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3619.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53670);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/14 15:20:34 $");

  script_cve_id("CVE-2010-2963", "CVE-2010-3067", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3874", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4078", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4164");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2010:1047-1)");
  script_summary(english:"Check for the kernel-3619 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of the openSUSE 11.1 kernel updates the kernel to
2.6.27.56 and fixes various security issues and other bugs.

Following security issues were fixed by this update: CVE-2010-2963: A
problem in the compat ioctl handling in video4linux allowed local
attackers with a video device plugged in to gain privileges on x86_64
systems.

CVE-2010-4157: A 32bit vs 64bit integer mismatch in gdth_ioctl_alloc
could lead to memory corruption in the GDTH driver.

CVE-2010-4164: A remote (or local) attacker communicating over X.25
could cause a kernel panic by attempting to negotiate malformed
facilities.

CVE-2010-3874: A minor heap overflow in the CAN network module was
fixed. Due to nature of the memory allocator it is likely not
exploitable.

CVE-2010-4158: A memory information leak in berkely packet filter
rules allowed local attackers to read uninitialized memory of the
kernel stack.

CVE-2010-4162: A local denial of service in the blockdevice layer was
fixed.

CVE-2010-3437: A range checking overflow in pktcdvd ioctl was fixed.

CVE-2010-4078: The sisfb_ioctl function in
drivers/video/sis/sis_main.c in the Linux kernel did not properly
initialize a certain structure member, which allowed local users to
obtain potentially sensitive information from kernel stack memory via
an FBIOGET_VBLANK ioctl call.

CVE-2010-4082: The viafb_ioctl_get_viafb_info function in
drivers/video/via/ioctl.c in the Linux kernel did not properly
initialize a certain structure member, which allowed local users to
obtain potentially sensitive information from kernel stack memory via
a VIAFB_GET_INFO ioctl call.

CVE-2010-4073: The ipc subsystem in the Linux kernel did not
initialize certain structures, which allowed local users to obtain
potentially sensitive information from kernel stack memory via vectors
related to the (1) compat_sys_semctl, (2) compat_sys_msgctl, and (3)
compat_sys_shmctl functions in ipc/compat.c; and the (4)
compat_sys_mq_open and (5) compat_sys_mq_getsetattr functions in
ipc/compat_mq.c.

CVE-2010-4072: The copy_shmid_to_user function in ipc/shm.c in the
Linux kernel did not initialize a certain structure, which allowed
local users to obtain potentially sensitive information from kernel
stack memory via vectors related to the shmctl system call and the
'old shm interface.'

CVE-2010-4083: The copy_semid_to_user function in ipc/sem.c in the
Linux kernel did not initialize a certain structure, which allowed
local users to obtain potentially sensitive information from kernel
stack memory via a (1) IPC_INFO, (2) SEM_INFO, (3) IPC_STAT, or (4)
SEM_STAT command in a semctl system call.

CVE-2010-3067: Integer overflow in the do_io_submit function in
fs/aio.c in the Linux kernel allowed local users to cause a denial of
service or possibly have unspecified other impact via crafted use of
the io_submit system call.

CVE-2010-3442: Multiple integer overflows in the snd_ctl_new function
in sound/core/control.c in the Linux kernel allowed local users to
cause a denial of service (heap memory corruption) or possibly have
unspecified other impact via a crafted (1) SNDRV_CTL_IOCTL_ELEM_ADD or
(2) SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call.

CVE-2010-4080: The snd_hdsp_hwdep_ioctl function in
sound/pci/rme9652/hdsp.c in the Linux kernel did not initialize a
certain structure, which allowed local users to obtain potentially
sensitive information from kernel stack memory via an
SNDRV_HDSP_IOCTL_GET_CONFIG_INFO ioctl call.

CVE-2010-4081: The snd_hdspm_hwdep_ioctl function in
sound/pci/rme9652/hdspm.c in the Linux kernel did not initialize a
certain structure, which allowed local users to obtain potentially
sensitive information from kernel stack memory via an
SNDRV_HDSPM_IOCTL_GET_CONFIG_INFO ioctl call."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-12/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=595215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=646045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653260"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.56-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.56-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-extra / etc");
}
