#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-1214.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40789);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/12/01 14:29:29 $");

  script_cve_id("CVE-2009-1389", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692");

  script_name(english:"openSUSE Security Update : kernel (kernel-1214)");
  script_summary(english:"Check for the kernel-1214 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Kernel was updated to 2.6.27.29 fixing
various bugs and security issues.

Following security issues were fixed: CVE-2009-2692: A missing NULL
pointer check in the socket sendpage function can be used by local
attackers to gain root privileges.

CVE-2009-2406: A kernel stack overflow when mounting eCryptfs
filesystems in parse_tag_11_packet() was fixed. Code execution might
be possible of ecryptfs is in use.

CVE-2009-2407: A kernel heap overflow when mounting eCryptfs
filesystems in parse_tag_3_packet() was fixed. Code execution might be
possible of ecryptfs is in use.

The compiler option -fno-delete-null-pointer-checks was added to the
kernel build, and the -fwrapv compiler option usage was fixed to be
used everywhere. This works around the compiler removing checks too
aggressively.

CVE-2009-1389: A crash in the r8169 driver when receiving large
packets was fixed. This is probably exploitable only in the local
network.

No CVE yet: A sigaltstack kernel memory disclosure was fixed.

The NULL page protection using mmap_min_addr was enabled (was disabled
before).

This update also adds the Microsoft Hyper-V drivers from upstream."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=402922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=467846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=489105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=504646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=511079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=511306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=512070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=513437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=513954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=517098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=518291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=519111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=519188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=520975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=521190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=521578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=523719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=524347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=525903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=526514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=530151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=530535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=531533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-debug-cvs20081020_2.6.27.29_0.1-1.32.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-trace-cvs20081020_2.6.27.29_0.1-1.32.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.29_0.1-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.29_0.1-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-debug-2.3.6_2.6.27.29_0.1-1.49.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-trace-2.3.6_2.6.27.29_0.1-1.49.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-debug-8.2.7_2.6.27.29_0.1-1.19.25") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-trace-8.2.7_2.6.27.29_0.1-1.19.25") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.29_0.1-2.40.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.29_0.1-2.40.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.29_0.1-89.11.18") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.29_0.1-89.11.18") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-ec2-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-ec2-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-ec2-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.29-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.29_0.1-2.1.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.29_0.1-2.1.12") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-trace-78_2.6.27.29_0.1-6.7.4") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-trace-0.8.4_2.6.27.29_0.1-0.1.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-debug-1.4_2.6.27.29_0.1-21.16.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-trace-1.4_2.6.27.29_0.1-21.16.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-debug-2.0.5_2.6.27.29_0.1-2.36.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-trace-2.0.5_2.6.27.29_0.1-2.36.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-debug-0.44_2.6.27.29_0.1-227.56.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-trace-0.44_2.6.27.29_0.1-227.56.14") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.29_0.1-2.8.55") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.29_0.1-2.8.55") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-debug-2008.09.03_2.6.27.29_0.1-5.50.37") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-trace-2008.09.03_2.6.27.29_0.1-5.50.37") ) flag++;

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
