#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2528-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94267);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/28 15:50:26 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4480", "CVE-2016-5238", "CVE-2016-5338", "CVE-2016-6258", "CVE-2016-7092", "CVE-2016-7094");
  script_bugtraq_id(69654);
  script_osvdb_id(111030, 136473, 136948, 136949, 137353, 138374, 138720, 138741, 138742, 138952, 139324, 139575, 139576, 142140, 143907, 143909);
  script_xref(name:"IAVB", value:"2016-B-0118");
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2016:2528-1) (Bunker Buster)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues. These security issues were
fixed :

  - CVE-2016-7094: Buffer overflow in Xen allowed local x86
    HVM guest OS administrators on guests running with
    shadow paging to cause a denial of service via a
    pagetable update (bsc#995792)

  - CVE-2016-7092: The get_page_from_l3e function in
    arch/x86/mm.c in Xen allowed local 32-bit PV guest OS
    administrators to gain host OS privileges via vectors
    related to L3 recursive pagetables (bsc#995785)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675)

  - CVE-2016-5338: The (1) esp_reg_read and (2)
    esp_reg_write functions allowed local guest OS
    administrators to cause a denial of service (QEMU
    process crash) or execute arbitrary code on the host via
    vectors related to the information transfer buffer
    (bsc#983984)

  - CVE-2016-5238: The get_cmd function in hw/scsi/esp.c
    might have allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via vectors related to reading from the
    information transfer buffer in non-DMA mode (bsc#982960)

  - CVE-2014-3672: The qemu implementation in libvirt Xen
    allowed local guest OS users to cause a denial of
    service (host disk consumption) by writing to stdout or
    stderr (bsc#981264)

  - CVE-2016-4441: The get_cmd function in the 53C9X Fast
    SCSI Controller (FSC) support did not properly check DMA
    length, which allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via unspecified vectors, involving an
    SCSI command (bsc#980724)

  - CVE-2016-4439: The esp_reg_write function in the 53C9X
    Fast SCSI Controller (FSC) support did not properly
    check command buffer length, which allowed local guest
    OS administrators to cause a denial of service
    (out-of-bounds write and QEMU process crash) or
    potentially execute arbitrary code on the host via
    unspecified vectors (bsc#980716)

  - CVE-2016-3710: The VGA module improperly performed
    bounds checking on banked access to video memory, which
    allowed local guest OS administrators to execute
    arbitrary code on the host by changing access modes
    after setting the bank register, aka the 'Dark Portal'
    issue (bsc#978164)

  - CVE-2016-4480: The guest_walk_tables function in
    arch/x86/mm/guest_walk.c in Xen did not properly handle
    the Page Size (PS) page table entry bit at the L4 and L3
    page table levels, which might have allowed local guest
    OS users to gain privileges via a crafted mapping of
    memory (bsc#978295)

  - CVE-2016-3960: Integer overflow in the x86 shadow
    pagetable code allowed local guest OS users to cause a
    denial of service (host crash) or possibly gain
    privileges by shadowing a superpage mapping (bsc#974038)

  - CVE-2016-3158: The xrstor function did not properly
    handle writes to the hardware FSW.ES bit when running on
    AMD64 processors, which allowed local guest OS users to
    obtain sensitive register content information from
    another guest by leveraging pending exception and mask
    bits (bsc#973188)

  - CVE-2016-4001: Buffer overflow in the
    stellaris_enet_receive function, when the Stellaris
    ethernet controller is configured to accept large
    packets, allowed remote attackers to cause a denial of
    service (QEMU crash) via a large packet (bsc#975130)

  - CVE-2016-4002: Buffer overflow in the mipsnet_receive
    function, when the guest NIC is configured to accept
    large packets, allowed remote attackers to cause a
    denial of service (memory corruption and QEMU crash) or
    possibly execute arbitrary code via a packet larger than
    1514 bytes (bsc#975138)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5338.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7094.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162528-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0357eead"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-xen-12786=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-devel-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-devel-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-libs-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-tools-domU-4.1.6_08-29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.40-29.1")) flag++;


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
