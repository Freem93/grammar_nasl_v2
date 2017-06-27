#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5920.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(35446);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2008-4933", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5134", "CVE-2008-5182", "CVE-2008-5702");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-5920)");
  script_summary(english:"Check for the kernel-5920 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 10.3 kernel was updated to fix various security problems
and bugs. Following security bugs were fixed :

CVE-2008-5702: Buffer underflow in the ibwdt_ioctl function in
drivers/watchdog/ib700wdt.c might allow local users to have an unknown
impact via a certain /dev/watchdog WDIOC_SETTIMEOUT IOCTL call.

CVE-2008-5079: net/atm/svc.c in the ATM subsystem allowed local users
to cause a denial of service (kernel infinite loop) by making two
calls to svc_listen for the same socket, and then reading a
/proc/net/atm/*vc file, related to corruption of the vcc table.

CVE-2008-5029: The __scm_destroy function in net/core/scm.c makes
indirect recursive calls to itself through calls to the fput function,
which allows local users to cause a denial of service (panic) via
vectors related to sending an SCM_RIGHTS message through a UNIX domain
socket and closing file descriptors.

CVE-2008-5134: Buffer overflow in the lbs_process_bss function in
drivers/net/wireless/libertas/scan.c in the libertas subsystem allowed
remote attackers to have an unknown impact via an 'invalid
beacon/probe response.'

CVE-2008-4933: Buffer overflow in the hfsplus_find_cat function in
fs/hfsplus/catalog.c allowed attackers to cause a denial of service
(memory corruption or system crash) via an hfsplus filesystem image
with an invalid catalog namelength field, related to the
hfsplus_cat_build_key_uni function.

CVE-2008-5025: Stack-based buffer overflow in the hfs_cat_find_brec
function in fs/hfs/catalog.c allowed attackers to cause a denial of
service (memory corruption or system crash) via an hfs filesystem
image with an invalid catalog namelength field, a related issue to
CVE-2008-4933.

CVE-2008-5182: The inotify functionality might allow local users to
gain privileges via unknown vectors related to race conditions in
inotify watch removal and umount."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/22");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.19-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.19-0.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-source / etc");
}
