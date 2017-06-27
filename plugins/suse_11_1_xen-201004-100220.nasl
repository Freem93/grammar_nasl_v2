#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xen-201004-2445.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46729);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/13 19:55:06 $");

  script_cve_id("CVE-2009-3525");

  script_name(english:"openSUSE Security Update : xen-201004 (openSUSE-SU-2010:0293-1)");
  script_summary(english:"Check for the xen-201004-2445 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Collective Xen 2010/04 Update, containing fixes for the following
issues :

bnc#576832 - pygrub, reiserfs: Fix on-disk structure definition
bnc#537370 - Xen on SLES 11 does not boot - endless loop in ATA
detection bnc#561912 - xend leaks memory bnc#564750 - Keyboard Caps
Lock key works abnormal under SLES11 xen guest OS. bnc#548443 - keymap
setting not preserved bnc#555152 - 'NAME' column in xentop (SLES11)
output limited to 10 characters unlike SLES10 bnc#553631 - L3:
diskpart will not run on windows 2008 bnc#548852 - DL585G2 - plug-in
PCI cards fail in IO-APIC mode bnc#529195

  - xend: disallow ! as a sxp separator bnc#550397 - xend:
    bootable flag of VBD not always of type int bnc#545470 -
    Xen vifname parameter is ignored when using type=ioemu
    in guest configuration file bnc#541945 - xm create -x
    command does not work in SLES 10 SP2 or SLES 11
    bnc#542525 - VUL-1: xen pygrub vulnerability bnc#481592
    and fate#306125 - Virtual machines are not able to boot
    from CD to allow upgrade to OES2SP1 (sle10 bug)
    bnc#553633 - Update breaks menu access keys in
    virt-viewer and still misses some key sequences. (sle10
    bug) fate#306720: xen: virt-manager cdrom handling.
    bnc#547590 - L3: virt-manager is unable of displaying
    VNC console on remote hosts bnc#572691 - libvird
    segfaults when trying to create a kvm guest bnc#573748 -
    L3: Virsh gives error Device 51712 not connected after
    updating libvirt modules bnc#548438 - libcmpiutil /
    libvirt-cim does not properly handle CIM_ prefixed
    bnc#513921 - Xen doesn't work get an eror when starting
    the install processes or starting a pervious installed
    DomU bnc#526855 - Cannot set MAC address for PV guest in
    vm-install"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-05/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=481592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=542525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=545470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=553631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=553633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=572691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen-201004 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmpiutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcmpiutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-cim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virt-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virt-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"libcmpiutil-0.5-15.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libcmpiutil-devel-0.5-15.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libvirt-0.4.6-11.16.26") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libvirt-cim-0.5.2-4.22.92") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libvirt-devel-0.4.6-11.16.26") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libvirt-python-0.4.6-11.16.26") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virt-manager-0.5.3-64.26.26") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virt-viewer-0.0.3-3.30.27") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vm-install-0.3.27-0.1.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-devel-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-doc-html-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-doc-pdf-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-kmp-debug-3.3.1_18546_24_2.6.27.45_0.2-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-kmp-default-3.3.1_18546_24_2.6.27.45_0.2-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-kmp-pae-3.3.1_18546_24_2.6.27.45_0.2-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-kmp-trace-3.3.1_18546_24_2.6.27.45_0.2-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-libs-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-tools-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xen-tools-domU-3.3.1_18546_24-0.4.13") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"xen-libs-32bit-3.3.1_18546_24-0.4.13") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
