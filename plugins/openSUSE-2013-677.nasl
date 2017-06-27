#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-677.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75130);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/26 00:30:55 $");

  script_cve_id("CVE-2012-6075", "CVE-2013-0151", "CVE-2013-1432", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1922", "CVE-2013-1952", "CVE-2013-2007", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078");
  script_bugtraq_id(57420, 57495, 59070, 59291, 59292, 59615, 59617, 59675, 59982, 60277, 60278, 60282, 60799);
  script_osvdb_id(89319, 89472, 92492, 92563, 92564, 92983, 92984, 93032, 93491, 93820, 93821, 93822, 94600);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2013:1404-1)");
  script_summary(english:"Check for the openSUSE-2013-677 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to 4.2.2, fixing lots of bugs and several security
issues.

Various upstream patches were also merged into this version by our
developers.

Detailed buglist :

  - bnc#824676 - Failed to setup devices for vm instance
    when start multiple vms simultaneously

  - bnc#817799 - sles9sp4 guest fails to start after
    upgrading to sles11 sp3

  - bnc#826882 - xen: CVE-2013-1432: XSA-58: Page reference
    counting error due to XSA-45/CVE-2013-1918 fixes

  - Add upstream patch to fix devid assignment in libxl
    27184-libxl-devid-fix.patch

  - bnc#823608 - xen: XSA-57: libxl allows guest write
    access to sensitive console related xenstore keys
    27178-libxl-Restrict-permissions-on-PV-console-device-xe
    nstore-nodes.patch

  - bnc#823011 - xen: XSA-55: Multiple vulnerabilities in
    libelf PV kernel handling

  - bnc#808269 - Fully Virtualized Windows VM install is
    failed on Ivy Bridge platforms with Xen kernel

  - bnc#801663 - performance of mirror lvm unsuitable for
    production block-dmmd

  - bnc#817904 - [SLES11SP3 BCS Bug] Crashkernel fails to
    boot after panic on XEN kernel SP3 Beta 4 and RC1

  - Upstream AMD Erratum patch from Jan

  - bnc#813675 - - xen: CVE-2013-1919: XSA-46: Several
    access permission issues with IRQs for unprivileged
    guests

  - bnc#820917 - CVE-2013-2076: xen: Information leak on
    XSAVE/XRSTOR capable AMD CPUs (XSA-52)

  - bnc#820919 - CVE-2013-2077: xen: Hypervisor crash due to
    missing exception recovery on XRSTOR (XSA-53)

  - bnc#820920 - CVE-2013-2078: xen: Hypervisor crash due to
    missing exception recovery on XSETBV (XSA-54)

  - bnc#808085 - aacraid driver panics mapping INT A when
    booting kernel-xen

  - bnc#817210 - openSUSE 12.3 Domain 0 doesn't boot with
    i915 graphics controller under Xen with VT-d enabled

  - bnc#819416 - xen: CVE-2013-2072: XSA-56: Buffer overflow
    in xencontrol Python bindings affecting xend

  - bnc#818183 - xen: CVE-2013-2007: XSA-51: qga set umask
    0077 when daemonizing

  - add lndir to BuildRequires

  - remove
    xen.migrate.tools_notify_restore_to_hangup_during_migrat
    ion_--abort_if_busy.patch It changed migration protocol
    and upstream wants a different solution

  - bnc#802221 - fix xenpaging readd
    xenpaging.qemu.flush-cache.patch

  - bnc#808269 - Fully Virtualized Windows VM install is
    failed on Ivy Bridge platforms with Xen kernel

  - Additional fix for bnc#816159
    CVE-2013-1918-xsa45-followup.patch

  - bnc#817068 - Xen guest with >1 sr-iov vf won't start

  - Update to Xen 4.2.2 c/s 26064 The following recent
    security patches are included in the tarball
    CVE-2013-0151-xsa34.patch (bnc#797285)
    CVE-2012-6075-xsa41.patch (bnc#797523)
    CVE-2013-1917-xsa44.patch (bnc#813673)
    CVE-2013-1919-xsa46.patch (bnc#813675)

  - bnc#816159 - xen: CVE-2013-1918: XSA-45: Several long
    latency operations are not preemptible

  - bnc#816163 - xen: CVE-2013-1952: XSA-49: VT-d interrupt
    remapping source validation flaw for bridges

  - bnc#809662 - can't use pv-grub to start domU (pygrub
    does work) xen.spec

  - bnc#814709 - Unable to create XEN virtual machines in
    SLED 11 SP2 on Kyoto

  - bnc#813673 - CVE-2013-1917: xen: Xen PV DoS
    vulnerability with SYSENTER

  - bnc#813675 - CVE-2013-1919: xen: Several access
    permission issues with IRQs for unprivileged guests

  - bnc#814059 - xen: qemu-nbd format-guessing due to
    missing format specification"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826882"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xen-debugsource-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-devel-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-debuginfo-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-debuginfo-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-debuginfo-4.2.2_06_k3.7.10_1.16-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-debuginfo-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-debuginfo-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-html-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-4.2.2_06-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.2.2_06-1.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
