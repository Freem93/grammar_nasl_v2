#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4749.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29248);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5904");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4749)");
  script_summary(english:"Check for the kernel-4749 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

++ CVE-2007-5500: A buggy condition in the ptrace attach logic can be
used by local attackers to hang the machine.

++ CVE-2007-5501: The tcp_sacktag_write_queue function in
net/ipv4/tcp_input.c allows remote attackers to cause a denial of
service (crash) via crafted ACK responses that trigger a NULL pointer
dereference.

++ CVE-2007-5904: Multiple buffer overflows in CIFS VFS allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via long SMB responses that trigger the overflows in
the SendReceive function.

This requires the attacker to set up a malicious Samba/CIFS server and
getting the client to connect to it.

and the following non security bugs :

++ Kernel update to 2.6.22.13 (includes the fixes for CVE-2007-5500
and CVE-2007-5501 described above)

++ patches.fixes/input-add-ms-vm-to-noloop.patch: add i8042.noloop
quirk for Microsoft Virtual Machine [#297546]

++ patches.fixes/mac80211_fix_scan.diff: Make per-SSID scanning work
[#299598] [#327684]

++ patches.drivers/kobil_sct_backport.patch: Fix segfault for Kobil
USB Plus cardreaders [#327664]

++ patches.arch/acpi_thermal_passive_blacklist.patch: Avoid critical
temp shutdowns on specific ThinkPad T4x(p) and R40 [#333043]

++ patches.fixes/microtek_hal.diff: Make the microtek driver work with
HAL [#339743]

++ patches.fixes/pci-fix-unterminated-pci_device_id-lists: fix
unterminated pci_device_id lists [#340527]

++ patches.fixes/nfsacl-retval.diff: knfsd: fix spurious EINVAL errors
on first access of new filesystem [#340873]"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt_debug-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.13-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.13-0.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-rt / etc");
}
