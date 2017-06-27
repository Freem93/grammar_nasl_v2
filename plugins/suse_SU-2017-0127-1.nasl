#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0127-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96529);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/30 15:10:04 $");

  script_cve_id("CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9381", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846", "CVE-2016-9907", "CVE-2016-9908", "CVE-2016-9911", "CVE-2016-9912", "CVE-2016-9913", "CVE-2016-9921", "CVE-2016-9922");
  script_osvdb_id(146388, 146391, 147657, 148129, 148253, 148254, 148268, 148291, 148375, 148376, 148377, 148394);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2017:0127-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix several issues. These security issues were
fixed :

  - CVE-2016-9102: Memory leak in the v9fs_xattrcreate
    function in hw/9pfs/9p.c in allowed local guest OS
    administrators to cause a denial of service (memory
    consumption and QEMU process crash) via a large number
    of Txattrcreate messages with the same fid number
    (bsc#1014256).

  - CVE-2016-9103: The v9fs_xattrcreate function in
    hw/9pfs/9p.c in allowed local guest OS administrators to
    obtain sensitive host heap memory information by reading
    xattribute values writing to them (bsc#1007454).

  - CVE-2016-9381: Improper processing of shared rings
    allowing guest administrators take over the qemu
    process, elevating their privilege to that of the qemu
    process (bsc#1009109)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013285).

  - CVE-2016-9845: The Virtio GPU Device emulator support as
    vulnerable to an information leakage issue while
    processing the 'VIRTIO_GPU_CMD_GET_CAPSET_INFO' command.
    A guest user/process could have used this flaw to leak
    contents of the host memory (bsc#1013767).

  - CVE-2016-9846: The Virtio GPU Device emulator support
    was vulnerable to a memory leakage issue while updating
    the cursor data in update_cursor_data_virgl. A guest
    user/process could have used this flaw to leak host
    memory bytes, resulting in DoS for the host
    (bsc#1013764).

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014109).

  - CVE-2016-9908: The Virtio GPU Device emulator support
    was vulnerable to an information leakage issue while
    processing the 'VIRTIO_GPU_CMD_GET_CAPSET' command. A
    guest user/process could have used this flaw to leak
    contents of the host memory (bsc#1014514).

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014111).

  - CVE-2016-9912: The Virtio GPU Device emulator support
    was vulnerable to a memory leakage issue while
    destroying gpu resource object in
    'virtio_gpu_resource_destroy'. A guest user/process
    could have used this flaw to leak host memory bytes,
    resulting in DoS for the host (bsc#1014112).

  - CVE-2016-9913: VirtFS was vulnerable to memory leakage
    issue via its '9p-handle' or '9p-proxy' backend drivers.
    A privileged user inside guest could have used this flaw
    to leak host memory, thus affecting other services on
    the host and/or potentially crash the Qemu process on
    the host (bsc#1014110). These non-security issues were
    fixed :

  - Fixed uint64 property parsing and add regression tests
    (bsc#937125)

  - Added a man page for kvm_stat

  - Fix crash in vte (bsc#1008519)

  - Various upstream commits targeted towards stable
    releases (bsc#1013341)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9846.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9907.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9912.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9922.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170127-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e6a371f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-68=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-68=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-68=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-ssh-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-ssh-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-debugsource-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-guest-agent-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-lang-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-tools-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-kvm-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-debugsource-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-kvm-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.6.2-39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"qemu-x86-2.6.2-39.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
