#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4929.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(30142);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-2242", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4997", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6417", "CVE-2008-0001", "CVE-2008-0007");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4929)");
  script_summary(english:"Check for the kernel-4929 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

CVE-2008-0007: Insufficient range checks in certain fault handlers
could be used by local attackers to potentially read or write kernel
memory.

CVE-2008-0001: Incorrect access mode checks could be used by local
attackers to corrupt directory contents and so cause denial of service
attacks or potentially execute code.

CVE-2007-5966: Integer overflow in the hrtimer_start function in
kernel/hrtimer.c in the Linux kernel before 2.6.23.10 allows local
users to execute arbitrary code or cause a denial of service (panic)
via a large relative timeout value. NOTE: some of these details are
obtained from third-party information.

CVE-2007-3843: The Linux kernel checked the wrong global variable for
the CIFS sec mount option, which might allow remote attackers to spoof
CIFS network traffic that the client configured for security
signatures, as demonstrated by lack of signing despite sec=ntlmv2i in
a SetupAndX request.

CVE-2007-2242: The IPv6 protocol allows remote attackers to cause a
denial of service via crafted IPv6 type 0 route headers
(IPV6_RTHDR_TYPE_0) that create network amplification between two
routers.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in Linux kernel
2.6.11 through 2.6.23 does not properly clear allocated memory in some
rare circumstances, which might allow local users to read sensitive
kernel data or cause a denial of service (crash).

CVE-2007-4308: The (1) aac_cfg_open and (2) aac_compat_ioctl functions
in the SCSI layer ioctl path in aacraid in the Linux kernel did not
check permissions for ioctls, which might have allowed local users to
cause a denial of service or gain privileges.

CVE-2007-3740: The CIFS filesystem, when Unix extension support is
enabled, does not honor the umask of a process, which allows local
users to gain privileges.

CVE-2007-3848: The Linux kernel allowed local users to send arbitrary
signals to a child process that is running at higher privileges by
causing a setuid-root parent process to die, which delivers an
attacker-controlled parent process death signal (PR_SET_PDEATHSIG).

CVE-2007-4997: Integer underflow in the ieee80211_rx function in
net/ieee80211/ieee80211_rx.c in the Linux kernel allowed remote
attackers to cause a denial of service (crash) via a crafted SKB
length value in a runt IEEE 802.11 frame when the
IEEE80211_STYPE_QOS_DATA flag is set, aka an 'off-by-two error.'

CVE-2007-6063: Buffer overflow in the isdn_net_setcfg function in
isdn_net.c in the Linux kernel allowed local users to have an unknown
impact via a crafted argument to the isdn_ioctl function.

CVE-none-yet: A failed change_hat call can result in an apparmored
task becoming unconfined (326546).

and the following non security bugs :

  - patches.suse/apparmor-r206-310260.diff: AppArmor - add
    audit capability names (310260).

  - patches.suse/apparmor-r326-240982.diff: AppArmor - fix
    memory corruption if policy load fails (240982).

  - patches.suse/apparmor-r400-221567.diff: AppArmor -
    kernel dead locks when audit back log occurs (221567).

  - patches.suse/apparmor-r405-247679.diff: AppArmor -
    apparmor fails to log link reject in complain mode
    (247679).

  - patches.suse/apparmor-r473-326556.diff: AppArmor - fix
    race on ambiguous deleted file name (326556).

  - patches.suse/apparmor-r479-257748.diff: AppArmor - fix
    kernel crash that can occur on profile removal (257748).

  - patches.fixes/usb_unusual_292931.diff: add quirk needed
    for 1652:6600 (292931).

  - patches.drivers/r8169-perform-a-PHY-reset-before.patch:
    r8169: perform a PHY reset before any other operation at
    boot time (345658).

  - patches.drivers/r8169-more-alignment-for-the-0x8168:
    refresh.

  - patches.fixes/usb_336850.diff: fix missing quirk leading
    to a device disconnecting under load (336850).

  - patches.fixes/avm-fix-capilib-locking: [ISDN] Fix random
    hard freeze with AVM cards. (#341894)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/01");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-kdump-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.8") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-default / kernel-kdump / kernel-source / etc");
}
