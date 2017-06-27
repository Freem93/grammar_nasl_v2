#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2473-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93935);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/28 15:50:26 $");

  script_cve_id("CVE-2016-6258", "CVE-2016-6259", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094");
  script_osvdb_id(142101, 142140, 142870, 142871, 142872, 142873, 143254, 143907, 143909, 143916);
  script_xref(name:"IAVB", value:"2016-B-0118");
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2016:2473-1) (Bunker Buster)");
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

  - CVE-2016-7092: The get_page_from_l3e function in
    arch/x86/mm.c in Xen allowed local 32-bit PV guest OS
    administrators to gain host OS privileges via vectors
    related to L3 recursive pagetables (bsc#995785).

  - CVE-2016-7093: Xen allowed local HVM guest OS
    administrators to overwrite hypervisor memory and
    consequently gain host OS privileges by leveraging
    mishandling of instruction pointer truncation during
    emulation (bsc#995789).

  - CVE-2016-7094: Buffer overflow in Xen allowed local x86
    HVM guest OS administrators on guests running with
    shadow paging to cause a denial of service via a
    pagetable update (bsc#995792).

  - CVE-2016-6836: Information leakage in
    vmxnet3_complete_packet (bsc#994761).

  - CVE-2016-6888: Integer overflow in packet initialisation
    in VMXNET3 device driver. Aprivileged user inside guest
    c... (bsc#994772).

  - CVE-2016-6833: Use after free while writing
    (bsc#994775).

  - CVE-2016-6835: Buffer overflow in
    vmxnet_tx_pkt_parse_headers() in vmxnet3
    deviceemulation. (bsc#994625).

  - CVE-2016-6834: An infinite loop during packet
    fragmentation (bsc#994421).

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675).

  - CVE-2016-6259: Xen did not implement Supervisor Mode
    Access Prevention (SMAP) whitelisting in 32-bit
    exception and event delivery, which allowed local 32-bit
    PV guest OS kernels to cause a denial of service
    (hypervisor and VM crash) by triggering a safety check
    (bsc#988676). These non-security issues were fixed :

  - bsc#991934: Hypervisor crash in csched_acct

  - bsc#992224: During boot of Xen Hypervisor, failed to get
    contiguous memory for DMA

  - bsc#955104: Virsh reports error 'one or more references
    were leaked after disconnect from hypervisor' when
    'virsh save' failed due to 'no response from client
    after 6 keepalive messages'

  - bsc#959552: Migration of HVM guest leads into libvirt
    segmentation fault

  - bsc#993665: Migration of xen guests finishes in: One or
    more references were leaked after disconnect from the
    hypervisor

  - bsc#959330: Guest migrations using virsh results in
    error 'Internal error: received hangup / error event on
    socket'

  - bsc#990500: VM virsh migration fails with keepalive
    error: ':virKeepAliveTimerInternal:143 : No response
    from client'

  - bsc#953518: Unplug also SCSI disks in
    qemu-xen-traditional for upstream unplug protocol

  - bsc#953518: xen_platform: unplug also SCSI disks in
    qemu-xen

  - bsc#971949: xl: Support (by ignoring) xl migrate --live.
    xl migrations are always live

  - bsc#970135: New virtualization project clock test
    randomly fails on Xen

  - bsc#990970: Add PMU support for Intel E7-8867 v4 (fam=6,
    model=79)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6259.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7094.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162473-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bffedd7a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1444=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1444=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1444=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/07");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-debugsource-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.5.3_10_k3.12.62_60.62-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.3_10_k3.12.62_60.62-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-debugsource-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.5.3_10_k3.12.62_60.62-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.3_10_k3.12.62_60.62-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.3_10-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-4.5.3_10-20.1")) flag++;


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
