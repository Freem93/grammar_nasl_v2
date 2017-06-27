#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-1097.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40360);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1961");

  script_name(english:"openSUSE Security Update : kernel (kernel-1097)");
  script_summary(english:"Check for the kernel-1097 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.1 kernel was updated to fix various bugs and several
security issues. It was also updated to the stable release 2.6.27.25.

Following security issues were fixed: CVE-2009-1961: A local denial of
service problem in the splice(2) system call was fixed.

CVE-2009-1389: A crash on r8169 network cards when receiving large
packets was fixed.

CVE-2009-1385: Integer underflow in the e1000_clean_rx_irq function in
drivers/net/e1000/e1000_main.c in the e1000 driver in the Linux
kernel, the e1000e driver in the Linux kernel, and Intel Wired
Ethernet (aka e1000) before 7.5.5 allows remote attackers to cause a
denial of service (panic) via a crafted frame size.

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c in the NFS
client implementation in the Linux kernel, when atomic_open is
available, does not check execute (aka EXEC or MAY_EXEC) permission
bits, which allows local users to bypass permissions and execute
files, as demonstrated by files on an NFSv4 fileserver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=185164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=191648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=395775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=439775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=450658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=475149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=476525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=476822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=481074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=485768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=491802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=493214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=500429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=501651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=505578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=506361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=507557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=511243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=516213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=516827"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189, 264, 362);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");
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

if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-debug-cvs20081020_2.6.27.25_0.1-1.32.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-trace-cvs20081020_2.6.27.25_0.1-1.32.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.25_0.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.25_0.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-debug-2.3.6_2.6.27.25_0.1-1.49.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-trace-2.3.6_2.6.27.25_0.1-1.49.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-debug-8.2.7_2.6.27.25_0.1-1.19.21") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-trace-8.2.7_2.6.27.25_0.1-1.19.21") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.25_0.1-2.40.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.25_0.1-2.40.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.25_0.1-89.11.17") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.25_0.1-89.11.17") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.25-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.25_0.1-2.1.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.25_0.1-2.1.11") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-trace-78_2.6.27.25_0.1-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-trace-0.8.4_2.6.27.25_0.1-0.1.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-debug-1.4_2.6.27.25_0.1-21.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-trace-1.4_2.6.27.25_0.1-21.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-debug-2.0.5_2.6.27.25_0.1-2.36.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-trace-2.0.5_2.6.27.25_0.1-2.36.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-debug-0.44_2.6.27.25_0.1-227.56.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-trace-0.44_2.6.27.25_0.1-227.56.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.25_0.1-2.8.50") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.25_0.1-2.8.50") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-debug-2008.09.03_2.6.27.25_0.1-5.50.35") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-trace-2008.09.03_2.6.27.25_0.1-5.50.35") ) flag++;

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
