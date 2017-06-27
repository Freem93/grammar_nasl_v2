#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5339.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33253);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-6282", "CVE-2008-0600", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136", "CVE-2008-2148");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-5339)");
  script_summary(english:"Check for the kernel-5339 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems:
CVE-2008-2136: A problem in SIT IPv6 tunnel handling could be used by
remote attackers to immediately crash the machine.

CVE-2008-1615: On x86_64 a denial of service attack could be used by
local attackers to immediately panic / crash the machine.

CVE-2008-2148: The permission checking in sys_utimensat was incorrect
and local attackers could change the filetimes of files they do not
own to the current time.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk could
potentially allow local attackers to execute code by timing file
locking.

CVE-2008-1375: Fixed a dnotify race condition, which could be used by
local attackers to potentially execute code.

CVE-2007-6282: A remote attacker could crash the IPSec/IPv6 stack by
sending a bad ESP packet. This requires the host to be able to receive
such packets (default filtered by the firewall).

CVE-2008-1367: Clear the 'direction' flag before calling signal
handlers. For specific not yet identified programs under specific
timing conditions this could potentially have caused memory corruption
or code execution.

And the following bugs (numbers are https://bugzilla.novell.com/
references) :

  - patches.fixes/input-add-amilo-pro-v-to-nomux.patch:
    Update the patch to include also 2030 model to nomux
    list (bnc#389169).

  - patches.apparmor/fix-net.diff: AppArmor: fix Oops in
    apparmor_socket_getpeersec_dgram() (bnc#378608).

  - patches.fixes/input-alps-update.patch: Input: fix the
    AlpsPS2 driver (bnc#357881).

- patches.arch/cpufreq_fix_acpi_driver_on_BIOS_changes.patch: CPUFREQ:
Check against freq changes from the BIOS (334378).

- patches.fixes/ieee1394-limit-early-node-speed-to-host-interf
ace-speed: ieee1394: limit early node speed to host interface speed
(381304).

  - patches.fixes/forcedeth_realtec_phy_fix: Fix a
    regression to the GA kernel for some forcedeth cards
    (bnc#379478)

  - pci-revert-SMBus-unhide-on-nx6110.patch: Do not unhide
    the SMBus on the HP Compaq nx6110, it's unsafe.

  - patches.drivers/e1000-disable-l1aspm.patch: Disable L1
    ASPM power savings for 82573 mobile variants, it's
    broken (bnc#254713, LTC34077).

  - patches.drivers/libata-improve-hpa-error-handling:
    libata: improve HPA error handling (365534).

  - rpm/kernel-binary.spec.in: Added Conflicts:
    libc.so.6()(64bit) to i386 arch (364433).

- patches.drivers/libata-disallow-sysfs-read-access-to-force-p aram:
libata: don't allow sysfs read access to force param (362599).

  - patches.suse/bonding-workqueue: Update to fix a hang
    when closing a bonding device (342994).

  - patches.fixes/mptspi-dv-renegotiate-oops: mptlinux
    crashes on kernel 2.6.22 (bnc#271749).

- patches.drivers/usb-update-sierra-and-option-device-ids-from

  -2.6.25-rc3.patch: USB: update sierra and option device
  ids from 2.6.25-rc3 (343167).

  - patches.arch/x86-nvidia-timer-quirk: Disable again
    (#302327) The PCI ID lists are not complete enough and
    let's have the same crap as mainline for this for now.

  - patches.fixes/input-add-lenovo-3000-n100-to-nomux.patch:
    Input: add Lenovo 3000 N100 to nomux blacklist
    (bnc#284013).

  - patches.suse/bonding-bh-locking: Add missing chunks. The
    SLES10 SP1 version of the patch was updated in May 2007
    but the openSuse 10.3 version was forgotten (260069).

- patches.fixes/knfsd-Allow-NFSv2-3-WRITE-calls-to-succeed-whe
n-krb.patch: knfsd: Allow NFSv2/3 WRITE calls to succeed when krb5i
etc is used. (348737).

- patches.fixes/md-fix-an-occasional-deadlock-in-raid5.patch: md: fix
an occasional deadlock in raid5 (357088).

  - patches.drivers/libata-quirk_amd_ide_mode: PCI: modify
    SATA IDE mode quirk (345124).

  - Fix section mismatch build failure w/ gcc 4.1.2. bug
    #361086.

  - patches.drivers/libata-implement-force-parameter:
    libata: implement libata.force module parameter
    (337610).

Lots of XEN Fixes (not detailed listed). Lots of RT Fixes (not
detailed listed).

  - Update to 2.6.22.18

  - removes upstreamed patch :

  - patches.fixes/vmsplice-pipe-exploit (CVE-2008-0600)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/"
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
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 94, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.18-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.18-0.2") ) flag++;

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
