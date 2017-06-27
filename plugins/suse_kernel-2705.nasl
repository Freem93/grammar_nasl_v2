#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-2705.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27293);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2006-5749", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-6106", "CVE-2007-0006", "CVE-2007-0772");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-2705)");
  script_summary(english:"Check for the kernel-2705 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2006-5751: An integer overflow in the networking
    bridge ioctl starting with Kernel 2.6.7 could be used by
    local attackers to overflow kernel memory buffers and
    potentially escalate privileges [#222656]

  - CVE-2006-6106: Multiple buffer overflows in the
    cmtp_recv_interopmsg function in the Bluetooth driver
    (net/bluetooth/cmtp/capi.c) in the Linux kernel allowed
    remote attackers to cause a denial of service (crash)
    and possibly execute arbitrary code via CAPI messages
    with a large value for the length of the (1) manu
    (manufacturer) or (2) serial (serial number) field.
    [#227603]

  - CVE-2006-5749: The isdn_ppp_ccp_reset_alloc_state
    function in drivers/isdn/isdn_ppp.c in the Linux kernel
    does not call the init_timer function for the ISDN PPP
    CCP reset state timer, which has unknown attack vectors
    and results in a system crash. [#229619]

  - CVE-2006-5753: Unspecified vulnerability in the
    listxattr system call in Linux kernel, when a 'bad
    inode' is present, allows local users to cause a denial
    of service (data corruption) and possibly gain
    privileges. [#230270]

  - CVE-2007-0006: The key serial number collision avoidance
    code in the key_alloc_serial function allows local users
    to cause a denial of service (crash) via vectors that
    trigger a null dereference. [#243003]

  - CVE-2007-0772: A remote denial of service problem on
    NFSv2 mounts with ACL enabled was fixed. [#244909]

Furthermore, it catches up to the mainline kernel, version 2.6.18.8,
and contains a large number of additional fixes for non security bugs."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-default / kernel-source / kernel-syms / etc");
}
