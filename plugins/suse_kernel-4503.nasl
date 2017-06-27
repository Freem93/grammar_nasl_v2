#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4503.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27299);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2007-4571", "CVE-2007-4573");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4503)");
  script_summary(english:"Check for the kernel-4503 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2007-4571: An information disclosure vulnerability
    in the ALSA driver can be exploited by local users to
    read sensitive data from the kernel memory.

  - CVE-2007-4573: It was possible for local user to become
    root by exploitable a bug in the IA32 system call
    emulation. This affects x86_64 platforms with kernel
    2.4.x and 2.6.x before 2.6.22.7 only.

and the following non security bugs :

  - supported.conf: Mark 8250 and 8250_pci as supported
    (only Xen kernels build them as modules) [#260686]

  - patches.fixes/bridge-module-get-put.patch: Module use
    count must be updated as bridges are created/destroyed
    [#267651]

  - patches.fixes/nfsv4-MAXNAME-fix.diff: knfsd: query
    filesystem for NFSv4 getattr of FATTR4_MAXNAME [#271803]

  - patches.fixes/sky2-tx-sum-resume.patch: sky2: fix
    transmit state on resume [#297132] [#326376]

  - patches.suse/reiserfs-add-reiserfs_error.diff:
    patches.suse/reiserfs-use-reiserfs_error.diff:
    patches.suse/reiserfs-buffer-info-for-balance.diff: Fix
    reiserfs_error() with NULL superblock calls [#299604]

  - patches.fixes/acpi_disable_C_states_in_suspend.patch:
    ACPI: disable lower idle C-states across suspend/resume
    [#302482]

  - kernel-syms.rpm: move the copies of the Modules.alias
    files from /lib/modules/... to /usr/src/linux-obj/... to
    avoid a file conflict between kernel-syms and other
    kernel-$flavor packages. The Modules.alias files in
    kernel-syms.rpm are intended for future use - [#307291]

  - patches.fixes/jffs2-fix-ACL-vs-mode-handling: Fix ACL
    vs. mode handling. [#310520]

- patches.drivers/libata-sata_sil24-fix-IRQ-clearing-race-on-I RQ_WOC:
sata_sil24: fix IRQ clearing race when PCIX_IRQ_WOC is used [#327536]

  - Update config files: Enabled CONFIG_DVB_PLUTO2 for i386
    since it's enabled everywhere else. [#327790]

- patches.drivers/libata-pata_ali-fix-garbage-PCI-rev-value: p
ata_ali: fix garbage PCI rev value in ali_init_chipset() [#328422]

  - patches.apparmor/apparmor-lsm-fix.diff:
    apparmor_file_mmap function parameters mismatch
    [#328423]

  - patches.drivers/libata-HPA-off-by-one-horkage: Fix HPA
    handling regression [#329584]"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/08");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.9-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.9-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.9-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.9-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.9-0.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.9-0.4") ) flag++;

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
