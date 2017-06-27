#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0674-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83580);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-4530", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0871");
  script_bugtraq_id(55878, 57176, 57740, 57743, 57838, 57986);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : kernel (SUSE-SU-2013:0674-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update fixes various security issues and bugs in the
SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed :

CVE-2013-0871: A race condition in ptrace(2) could be used by local
attackers to crash the kernel and/or execute code in kernel context.

CVE-2013-0160: Avoid side channel information leaks from the
ptys via ptmx, which allowed local attackers to guess
keypresses.

CVE-2012-4530: Avoid leaving bprm->interp on the stack which
might have leaked information from the kernel to userland
attackers.

CVE-2013-0268: The msr_open function in
arch/x86/kernel/msr.c in the Linux kernel allowed local
users to bypass intended capability restrictions by
executing a crafted application as root, as demonstrated by
msr32.c.

CVE-2013-0216: The Xen netback functionality in the Linux
kernel allowed guest OS users to cause a denial of service
(loop) by triggering ring pointer corruption.

CVE-2013-0231: The pciback_enable_msi function in the PCI
backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for
the Linux kernel allowed guest OS users with PCI device
access to cause a denial of service via a large number of
kernel log messages. NOTE: some of these details are
obtained from third-party information.

Also the following non-security bugs have been fixed :

S/390 :

  - s390x: tty struct used after free (bnc#809692,
    LTC#90216).

  - s390x/kernel: sched_clock() overflow (bnc#799611,
    LTC#87978).

  - qeth: set new mac even if old mac is gone
    (bnc#789012,LTC#86643).

  - qeth: set new mac even if old mac is gone (2)
    (bnc#792697,LTC#87138).

  - qeth: fix deadlock between recovery and bonding driver
    (bnc#785101,LTC#85905).

  - dasd: check count address during online setting
    (bnc#781485,LTC#85346).

  - hugetlbfs: add missing TLB invalidation
    (bnc#781485,LTC#85463).

  - s390/kernel: make user-access pagetable walk code huge
    page aware (bnc#781485,LTC#85455).

XEN :

  - xen/netback: fix netbk_count_requests().

  - xen: properly bound buffer access when parsing
    cpu/availability.

  - xen/scsiback/usbback: move cond_resched() invocations to
    proper place.

  - xen/pciback: properly clean up after calling
    pcistub_device_find().

  - xen: add further backward-compatibility configure
    options.

  - xen/PCI: suppress bogus warning on old hypervisors.

  - xenbus: fix overflow check in xenbus_dev_write().

  - xen/x86: do not corrupt %eip when returning from a
    signal handler.

Other :

  - kernel: Restrict clearing TIF_SIGPENDING (bnc#742111).

  - kernel: recalc_sigpending_tsk fixes (bnc#742111).

  - xfs: Do not reclaim new inodes in xfs_sync_inodes()
    (bnc#770980).

  - jbd: Avoid BUG_ON when checkpoint stalls (bnc#795335).

  - reiserfs: Fix int overflow while calculating free space
    (bnc#795075).

  - cifs: clarify the meaning of tcpStatus == CifsGood
    (bnc#769093).

  - cifs: do not allow cifs_reconnect to exit with NULL
    socket pointer (bnc#769093).

  - cifs: switch to seq_files (bnc#776370).

  - scsi: fix check of PQ and PDT bits for WLUNs
    (bnc#765687).

  - hugetlb: preserve hugetlb pte dirty state (bnc#790236).

  - poll: enforce RLIMIT_NOFILE in poll() (bnc#787272).

  - proc: fix ->open less usage due to ->proc_fops flip
    (bnc#776370).

  - rpm/kernel-binary.spec.in: Ignore kabi errors if
    %%ignore_kabi_badness is defined. This is used in the
    Kernel:* projects in the OBS.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=2b51bf3e02179f8f70c7b2ada2571a2d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0cb7e4a"
  );
  # http://download.suse.com/patch/finder/?keywords=7cf4de409b28c5f187bc1e9f71ccd64f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bda531dd"
  );
  # http://download.suse.com/patch/finder/?keywords=ac5626f6e7f483c6dac1cc5fe253fcf9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c96e0858"
  );
  # http://download.suse.com/patch/finder/?keywords=ba0e542087a9075aed8c17a29d5f1cb8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?381762ee"
  );
  # http://download.suse.com/patch/finder/?keywords=dba6fc0fdae22199ec260695a6d2179e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?536896a0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/742111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/765687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/781485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/785101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/790236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/792697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/795075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/795335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/799611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/800280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/801178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/802642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/804154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/809692"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130674-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa37e2a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-default-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-source-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-syms-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-default-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-source-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-syms-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.101.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.101.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
