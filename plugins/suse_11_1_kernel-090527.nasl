#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-932.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40250);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-1192", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1360", "CVE-2009-1439");

  script_name(english:"openSUSE Security Update : kernel (kernel-932)");
  script_summary(english:"Check for the kernel-932 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update for openSUSE 11.1 fixes lots of bugs and some
security issues. The kernel was also updated to the 2.6.27.23 stable
release.

Following security issues have been fixed: CVE-2009-1439: Buffer
overflow in fs/cifs/connect.c in CIFS in the Linux kernel 2.6.29 and
earlier allows remote attackers to cause a denial of service (crash)
or potential code execution via a long nativeFileSystem field in a
Tree Connect response to an SMB mount request.

This requires that kernel can be made to mount a 'cifs' filesystem
from a malicious CIFS server.

CVE-2009-1337: The exit_notify function in kernel/exit.c in the Linux
kernel did not restrict exit signals when the CAP_KILL capability is
held, which allows local users to send an arbitrary signal to a
process by running a program that modifies the exit_signal field and
then uses an exec system call to launch a setuid application.

The GCC option -fwrapv has been added to compilation to work around
potentially removing integer overflow checks.

CVE-2009-1265: Integer overflow in rose_sendmsg (sys/net/af_rose.c) in
the Linux kernel might allow attackers to obtain sensitive information
via a large length value, which causes 'garbage' memory to be sent.

CVE-2009-1242: The vmx_set_msr function in arch/x86/kvm/vmx.c in the
VMX implementation in the KVM subsystem in the Linux kernel on the
i386 platform allows guest OS users to cause a denial of service
(OOPS) by setting the EFER_LME (aka 'Long mode enable') bit in the
Extended Feature Enable Register (EFER) model-specific register, which
is specific to the x86_64 platform.

CVE-2009-1360: The __inet6_check_established function in
net/ipv6/inet6_hashtables.c in the Linux kernel, when Network
Namespace Support (aka NET_NS) is enabled, allows remote attackers to
cause a denial of service (NULL pointer dereference and system crash)
via vectors involving IPv6 packets.

CVE-2009-1192: drivers/char/agp/generic.c in the agp subsystem in the
Linux kernel does not zero out pages that may later be available to a
user-space process, which allows local users to obtain sensitive
information by reading these pages.

Additionaly a lot of bugs have been fixed and are listed in the RPM
changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=408304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=459065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=460284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=464360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=467518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=474062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=483706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=489005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=489105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=491289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=491430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=493392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=493991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=494463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=500508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=505831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=505925"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-trace");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kvm-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lirc-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-debug-cvs20081020_2.6.27.23_0.1-1.32.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-trace-cvs20081020_2.6.27.23_0.1-1.32.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.23_0.1-1.7.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.23_0.1-1.7.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-debug-2.3.6_2.6.27.23_0.1-1.49.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-trace-2.3.6_2.6.27.23_0.1-1.49.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-debug-8.2.7_2.6.27.23_0.1-1.19.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-trace-8.2.7_2.6.27.23_0.1-1.19.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.23_0.1-2.40.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.23_0.1-2.40.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.23_0.1-89.11.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.23_0.1-89.11.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.23-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.23_0.1-2.1.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.23_0.1-2.1.8") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-trace-78_2.6.27.23_0.1-6.6.20") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-trace-0.8.4_2.6.27.23_0.1-0.1.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-debug-1.4_2.6.27.23_0.1-21.15.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-trace-1.4_2.6.27.23_0.1-21.15.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-debug-2.0.5_2.6.27.23_0.1-2.36.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-trace-2.0.5_2.6.27.23_0.1-2.36.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-debug-0.44_2.6.27.23_0.1-227.56.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-trace-0.44_2.6.27.23_0.1-227.56.10") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.23_0.1-2.8.32") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.23_0.1-2.8.32") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-debug-2008.09.03_2.6.27.23_0.1-5.50.25") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-trace-2008.09.03_2.6.27.23_0.1-5.50.25") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kvm-kmp-trace-78_2.6.27.23_0.1-6.6.21") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.23_0.1-2.8.33") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.23_0.1-2.8.33") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aufs-kmp-debug / aufs-kmp-trace / brocade-bfa-kmp-debug / etc");
}
