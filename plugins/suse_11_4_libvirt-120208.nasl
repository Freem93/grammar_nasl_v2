#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libvirt-5774.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75931);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2012-0029");
  script_osvdb_id(78506);

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-SU-2012:0347-1)");
  script_summary(english:"Check for the libvirt-5774 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update 2012/02 for Xen provides fixes for the
following reports :

Xen ===

  - 649209: Fix Xen live migrations being slow

  - 683580: Fix hangs during boot up after the message
    'Enabled directed EOI with ioapic_ack_old on!

  - 691256: unable to open a connection to the XEN
    Hypervisor

  - 694863: Fix kexec fails in xen

  - 701686: kdump hangs on megaraid_sas driver

  - 704160: crm resource migrate fails with xen machines

  - 706106: Fix Inconsistent reporting of VM names during
    migration

  - 706574: xm console DomUName hang after 'xm save/restore'
    of PVM on the latest Xen

  - 712051: Fix xen: IOMMU fault livelock

  - 712823: Xen guest does not start reliable when rebooted

  - 714183: Since last update Xen VM's don't start if the
    name contains dots (as in 'example.mydomain.com')

  - 715655: No support for performance counters for Westmere
    E7-8837 and SandyBridge i5-2500

  - 716695: dom-us using tap devices will not start

  - 725169: xen-4.0.2_21511_03-0.5.3: bootup hangs

  - 726332: Xen changeset 21326 introduces considerable
    performance hit

  - 727515: Fragmented packets hang network boot of HVM
    guest

  - 732782: xm create hangs when maxmen value is enclosed in
    'quotes'

  - 734826: xm rename doesn't work anymore

  - 736824: Microcode patches for AMD's 15h processors panic
    the system

  - 739585: Xen block-attach fails after repeated
    attach/detach

  - 740165: Fix heap overflow in e1000 device emulation

libvirt =======

  - 728681: libvirtd litters syslog with
    'interfaceGetXMLDesc:355 : internal error' messages when
    using virt-manager

virt-utils ==========

  - Add Support for creating images that can be run on
    Microsoft Hyper-V host (Fix vpc file format. Add support
    for fixed disks)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=683580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=701686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740165"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libvirt-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-client-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-client-debuginfo-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-debuginfo-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-debugsource-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-devel-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-python-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libvirt-python-debuginfo-0.8.8-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virt-utils-1.1.5-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-debugsource-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-devel-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-html-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-pdf-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-debuginfo-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-debuginfo-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-debuginfo-4.0.3_01_k2.6.37.6_0.11-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-debuginfo-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-debuginfo-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-4.0.3_01-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-debuginfo-4.0.3_01-0.2.1") ) flag++;

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
