#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-271.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75312);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-2212", "CVE-2013-4494", "CVE-2013-4551", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6400", "CVE-2013-6885", "CVE-2014-1642", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-1950");
  script_bugtraq_id(61424, 63494, 63625, 63931, 63933, 63983, 64195, 65097, 65125, 65414, 65419, 65424, 65529);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2014:0483-1)");
  script_summary(english:"Check for the openSUSE-2014-271 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix various bugs and security issues :

Update to Xen version 4.2.4 c/s 26280.

  - bnc#861256 - CVE-2014-1950: xen: XSA-88: use-after-free
    in xc_cpupool_getinfo() under memory pressure. (fix
    included with update)

  - bnc#863297: xend/pvscsi: recognize also SCSI CDROM
    devices

  - bnc#858496 - CVE-2014-1642: Xen: XSA-83: Out-of-memory
    condition yielding memory corruption during IRQ setup

  - bnc#860163 - xen: XSA-84: integer overflow in several
    XSM/Flask hypercalls (CVE-2014-1891 CVE-2014-1892
    CVE-2014-1893 CVE-2014-1894)

  - bnc#860165 - CVE-2014-1895: xen: XSA-85: Off-by-one
    error in FLASK_AVC_CACHESTAT hypercall

  - bnc#860300 - CVE-2014-1896: xen: XSA-86: libvchan
    failure handling malicious ring indexes

  - bnc#860302 - CVE-2014-1666: xen: XSA-87:
    PHYSDEVOP_{prepare,release}_msix exposed to unprivileged
    guests

  - bnc#858311 - Server is not booting in kernel XEN after
    latest updates - (XEN) setup 0000:00:18.0 for d0 failed
    (-19)

  - bnc#858496 - CVE-2014-1642: Xen: XSA-83: Out-of-memory
    condition yielding memory corruption during IRQ setup

  - bnc#853049 - CVE-2013-6885: xen: XSA-82: Guest
    triggerable AMD CPU erratum may cause host hang

  - bnc#853048 - CVE-2013-6400: xen: XSA-80: IOMMU TLB
    flushing may be inadvertently suppressed

  - bnc#831120 - CVE-2013-2212: xen: XSA-60: Excessive time
    to disable caching with HVM guests with PCI passthrough

  - bnc#848014 - [HP HPS] Xen hypervisor panics on 8-blades
    nPar with 46-bit memory addressing

  - bnc#833251 - [HP BCS SLES11 Bug]: In HPs UEFI x86_64
    platform and with xen environment, in booting stage ,xen
    hypervisor will panic.

  - pygrub: Support (/dev/xvda) style disk specifications

  - bnc#849667 - CVE-2014-1895: xen: XSA-74: Lock order
    reversal between page_alloc_lock and mm_rwlock

  - bnc#849668 - CVE-2013-4554: xen: XSA-76: Hypercalls
    exposed to privilege rings 1 and 2 of HVM guests

  - bnc#842417 - In HPs UEFI x86_64 platform and sles11sp3
    with xen environment, dom0 will soft lockup on multiple
    blades nPar.

  - bnc#848014 - [HP HPS] Xen hypervisor panics on 8-blades
    nPar with 46-bit memory addressing

  - bnc#846849 - Soft lockup with PCI passthrough and many
    VCPUs

  - bnc#833483 - Boot Failure with xen kernel in UEFI mode
    with error 'No memory for trampoline'

  - bnc#849665 - CVE-2013-4551: xen: XSA-75: Host crash due
    to guest VMX instruction execution

  - The upstream version of checking for xend when using the
    'xl' command is used is not working.

  - bnc#840997 - It is possible to start a VM twice on the
    same node.

  - bnc#848657 - xen: CVE-2013-4494: XSA-73: Lock order
    reversal between page allocation and grant table locks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-04/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863297"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xen-debugsource-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-devel-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-debuginfo-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-debuginfo-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-debuginfo-4.2.4_02_k3.7.10_1.28-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-debuginfo-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-debuginfo-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-html-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-4.2.4_02-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.2.4_02-1.26.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
