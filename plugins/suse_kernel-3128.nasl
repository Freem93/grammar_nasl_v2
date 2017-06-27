#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3128.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27294);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2007-1000", "CVE-2007-1357", "CVE-2007-1388", "CVE-2007-1592");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-3128)");
  script_summary(english:"Check for the kernel-3128 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2007-1000 A NULL pointer dereference in the IPv6
    sockopt handling can be used by local attackers to read
    arbitrary kernel memory and so gain access to private
    information.

  - CVE-2007-1388 A NULL pointer dereference could be used
    by local attackers to cause a Oops / crash of the
    machine.

  - CVE-2007-1592 A possible double free in the
    ipv6/flowlabel handling was fixed.

  - CVE-2007-1357 A remote denial of service attack in the
    AppleTalk protocol handler was fixed. This attack is
    only possible on the local subnet, and requires the
    AppleTalk protocol module to be loaded (which is not
    done by default).

and the following non security bugs :

  - patches.fixes/visor_write_race.patch: fix race allowing
    overstepping memory limit in visor_write (Mainline:
    2.6.21)

  - patches.drivers/libata-ide-via-add-PCI-IDs:
    via82cxxx/pata_via: backport PCI IDs (254158).

  - libata: implement HDIO_GET_IDENTITY (255413).

  - sata_sil24: Add Adaptec 1220SA PCI ID. (Mainline:
    2.6.21)

  - ide: backport hpt366 from devel tree (244502).

  - mm: fix madvise infinine loop (248167).

  - libata: hardreset on SERR_INTERNAL (241334).

  - limited WPA support for prism54 (207944)

  - jmicron: match class instead of function number (224784,
    207707)

  - ahci: RAID mode SATA patch for Intel ICH9M (Mainline:
    2.6.21)

  - libata: blacklist FUJITSU MHT2060BH for NCQ (Mainline:
    2.6.21)

  - libata: add missing PM callbacks. (Mainline: 2.6.20)

  - patches.fixes/nfs-readdir-timestamp: Set meaningful
    value for fattr->time_start in readdirplus results.
    (244967).

  - patches.fixes/usb_volito.patch: wacom volito tablet not
    working (#248832).

  - patches.fixes/965-fix: fix detection of aperture size
    versus GTT size on G965 (#258013).

  - patches.fixes/sbp2-MODE_SENSE-fix.diff: use proper MODE
    SENSE, fixes recognition of device properties (261086)

  - patches.fixes/ipt_CLUSTERIP_refcnt_fix:
    ipv4/netfilter/ipt_CLUSTERIP.c - refcnt fix (238646)

  - patches.fixes/reiserfs-fix-vs-13060.diff: reiserfs: fix
    corruption with vs-13060 (257735).

  - patches.drivers/ati-rs400_200-480-disable-msi:
    pci-quirks: disable MSI on RS400-200 and RS480 (263893).

  - patches.drivers/libata-ahci-ignore-interr-on-SB600:
    ahci.c: walkaround for SB600 SATA internal error issue
    (#264792).

Furthermore, CONFIG_USB_DEVICEFS has been re-enabled to allow use of
USB in legacy applications like VMware. (#210899)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.3") ) flag++;

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
