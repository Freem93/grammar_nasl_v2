#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4752.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29880);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-4308", "CVE-2007-4573", "CVE-2007-4997", "CVE-2007-5904", "CVE-2007-6063");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4752)");
  script_summary(english:"Check for the kernel-4752 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

++ CVE-2007-3104: The sysfs_readdir function in the Linux kernel 2.6
allows local users to cause a denial of service (kernel OOPS) by
dereferencing a NULL pointer to an inode in a dentry.

++ CVE-2007-4997: A 2 byte buffer underflow in the ieee80211 stack was
fixed, which might be used by attackers in the local WLAN reach to
crash the machine.

++ CVE-2007-3740: The CIFS filesystem, when Unix extension support is
enabled, did not honor the umask of a process, which allowed local
users to gain privileges.

++ CVE-2007-4573: It was possible for local user to become root by
exploiting a bug in the IA32 system call emulation. This problem
affects the x86_64 platform only, on all distributions.

This problem was fixed for regular kernels, but had not been fixed for
the XEN kernels. This update fixes the problem also for the XEN
kernels.

++ CVE-2007-4308: The (1) aac_cfg_open and (2) aac_compat_ioctl
functions in the SCSI layer ioctl path in aacraid did not check
permissions for ioctls, which might have allowed local users to cause
a denial of service or gain privileges.

++ CVE-2007-3843: The Linux kernel checked the wrong global variable
for the CIFS sec mount option, which might allow remote attackers to
spoof CIFS network traffic that the client configured for security
signatures, as demonstrated by lack of signing despite sec=ntlmv2i in
a SetupAndX request.

++ CVE-2007-5904: Multiple buffer overflows in CIFS VFS in the Linux
kernel allowed remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via long SMB responses that
trigger the overflows in the SendReceive function.

This requires the attacker to mis-present / replace a CIFS server the
client machine is connected to.

++ CVE-2007-6063: Buffer overflow in the isdn_net_setcfg function in
isdn_net.c in the Linux kernel allowed local users to have an unknown
impact via a crafted argument to the isdn_ioctl function.

Furthermore, this kernel catches up to the SLE 10 state of the kernel,
with numerous additional fixes."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-um");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"kernel-bigsmp-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-debug-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-default-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-kdump-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-smp-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-source-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-syms-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-um-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xen-2.6.16.54-0.2.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xenpae-2.6.16.54-0.2.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-kdump / etc");
}
