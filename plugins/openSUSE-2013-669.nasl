#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-669.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75129);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2013-1432", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2211");
  script_bugtraq_id(58880, 59291, 59292, 59293, 59615, 59617, 59982, 60277, 60278, 60282, 60721, 60799);
  script_osvdb_id(92050, 92563, 92564, 92565, 92983, 92984, 93491, 93820, 93821, 93822, 94464, 94600);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2013:1392-1)");
  script_summary(english:"Check for the openSUSE-2013-669 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to 4.1.5 release. It fixes various bugs and security
issues.

Issues fixed separately from the 4.1.5 release :

  - bnc#824676 - Failed to setup devices for vm instance
    when start multiple vms simultaneously 

  - bnc#XXXXXX - xen: CVE-2013-XXXX: XSA-61: suppress device
    assignment to HVM guest when there is no IOMMU

  - Various upstream patches from Jan were integrated.

  - bnc#823786 - migrate.py support of short options dropped
    by PTF

  - bnc#803712 - after live migration rcu_sched_state
    detected stalls add new option xm migrate --min_remaing
    <num>

  - CVE-2013-1432 / bnc#826882 - xen: XSA-58: x86: fix page
    refcount handling in page table pin error path

  - CVE-2013-2211 / bnc#823608 - xen: XSA-57: libxl allows
    guest write access to sensitive console related xenstore
    keys

  - bnc#823011 - xen: XSA-55: Multiple vulnerabilities in
    libelf PV kernel handling

  - bnc#801663 - performance of mirror lvm unsuitable for
    production

  - CVE-2013-1918/ bnc#816159 - xen: CVE-2013-1918: XSA-45:
    Several long latency operations are not preemptible

  - CVE-2013-1952 / bnc#816163 - xen: CVE-2013-1952: XSA-49:
    VT-d interrupt remapping source validation flaw for
    bridges

  - CVE-2013-2076 / bnc#820917 - CVE-2013-2076: xen:
    Information leak on XSAVE/XRSTOR capable AMD CPUs
    (XSA-52)

  - CVE-2013-2077 / bnc#820919 - CVE-2013-2077: xen:
    Hypervisor crash due to missing exception recovery on
    XRSTOR (XSA-53)

  - CVE-2013-2078 / bnc#820920 - CVE-2013-2078: xen:
    Hypervisor crash due to missing exception recovery on
    XSETBV (XSA-54)

  - CVE-2013-2072 / bnc#819416 - xen: CVE-2013-2072: XSA-56:
    Buffer overflow in xencontrol Python bindings affecting
    xend 

  - Update to Xen 4.1.5 c/s 23509 There were many xen.spec
    file patches dropped as now being included in the 4.1.5
    tarball.

  - CVE-2013-1918 / bnc#816159 - xen: XSA-45: Several long
    latency operations are not preemptible

  - CVE-2013-1952 / bnc#816163 - xen: XSA-49: VT-d interrupt
    remapping source validation flaw for bridges

  - bnc#809662 - can't use pv-grub to start domU (pygrub
    does work)

  - CVE-2013-1917 / bnc#813673 - xen: Xen PV DoS
    vulnerability with SYSENTER

  - CVE-2013-1919 / bnc#813675 - xen: Several access
    permission issues with IRQs for unprivileged guests

  - CVE-2013-1920 / bnc#813677 - xen: Potential use of freed
    memory in event channel operations

  - bnc#814709 - Unable to create XEN virtual machines in
    SLED 11 SP2 on Kyoto"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803712"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816156"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823786"
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
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"xen-debugsource-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-devel-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-debuginfo-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-debuginfo-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-debuginfo-4.1.5_04_k3.4.47_2.38-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-debuginfo-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-debuginfo-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-html-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-4.1.5_04-5.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.5_04-5.29.1") ) flag++;

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
