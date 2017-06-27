#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-750.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86909);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/18 15:10:39 $");

  script_cve_id("CVE-2014-0222", "CVE-2015-3259", "CVE-2015-4037", "CVE-2015-5154", "CVE-2015-5165", "CVE-2015-5166", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971", "CVE-2015-7972");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2015-750)");
  script_summary(english:"Check for the openSUSE-2015-750 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to fix 12 security issues.

These security issues were fixed :

  - CVE-2015-7972: Populate-on-demand balloon size
    inaccuracy can crash guests (bsc#951845).

  - CVE-2015-7969: Leak of main per-domain vcpu pointer
    array (DoS) (bsc#950703).

  - CVE-2015-7969: Leak of per-domain profiling-related vcpu
    pointer array (DoS) (bsc#950705).

  - CVE-2015-7971: Some pmu and profiling hypercalls log
    without rate limiting (bsc#950706).

  - CVE-2015-4037: Insecure temporary file use in
    /net/slirp.c (bsc#932267).

  - CVE-2014-0222: Validate L2 table size to avoid integer
    overflows (bsc#877642).

  - CVE-2015-7835: Uncontrolled creation of large page
    mappings by PV guests (bsc#950367).

  - CVE-2015-7311: libxl fails to honour readonly flag on
    disks with qemu-xen (bsc#947165).

  - CVE-2015-5165: QEMU leak of uninitialized heap memory in
    rtl8139 device model (bsc#939712).

  - CVE-2015-5166: Use after free in QEMU/Xen block unplug
    protocol (bsc#939709).

  - CVE-2015-5154: Host code execution via IDE subsystem
    CD-ROM (bsc#938344).

  - CVE-2015-3259: xl command line config handling stack
    overflow (bsc#935634).

These non-security issues were fixed :

  - bsc#907514: Bus fatal error and sles12 sudden reboot has
    been observed

  - bsc#910258: SLES12 Xen host crashes with FATAL NMI after
    shutdown of guest with VT-d NIC

  - bsc#918984: Bus fatal error and sles11-SP4 sudden reboot
    has been observed

  - bsc#923967: Partner-L3: Bus fatal error and sles11-SP3
    sudden reboot has been observed

  - bsc#901488: Intel ixgbe driver assigns rx/tx queues per
    core resulting in irq problems on servers with a large
    amount of CPU cores

  - bsc#945167: Running command xl pci-assignable-add
    03:10.1 secondly show errors

  - bsc#949138: Setting vcpu affinity under Xen causes
    libvirtd abort

  - bsc#944463: VUL-0: CVE-2015-5239: qemu-kvm: Integer
    overflow in vnc_client_read() and protocol_client_msg()

  - bsc#944697: VUL-1: CVE-2015-6815: qemu: net: e1000:
    infinite loop issue

  - bsc#925466: Kdump does not work in a XEN environment"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=923967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951845"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.3_02_k3.16.7_29-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.3_02_k3.16.7_29-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.3_02_k3.16.7_29-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.3_02_k3.16.7_29-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.3_02-30.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.3_02-30.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
