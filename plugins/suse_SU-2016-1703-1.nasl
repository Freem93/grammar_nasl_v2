#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1703-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93170);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/03/08 15:07:21 $");

  script_cve_id("CVE-2015-5745", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4952");
  script_osvdb_id(125847, 131399, 131668, 131793, 131824, 132136, 132210, 132257, 132466, 132467, 132549, 132550, 132759, 132798, 133524, 133811, 133847, 134888, 135159, 135279, 135305, 135338, 136948, 136949, 137159, 137352, 138373, 138374, 138741, 138742, 138951);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2016:1703-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix 29 security issues.

These security issues were fixed :

  - CVE-2016-4439: Avoid OOB access in 53C9X emulation
    (bsc#980711)

  - CVE-2016-4441: Avoid OOB access in 53C9X emulation
    (bsc#980723)

  - CVE-2016-4952: Avoid OOB access in Vmware PV SCSI
    emulation (bsc#981266)

  - CVE-2015-8817: Avoid OOB access in PCI dma I/O
    (bsc#969121)

  - CVE-2015-8818: Avoid OOB access in PCI dma I/O
    (bsc#969122)

  - CVE-2016-3710: Fixed VGA emulation based OOB access with
    potential for guest escape (bsc#978158)

  - CVE-2016-3712: Fixed VGa emulation based DOS and OOB
    read access exploit (bsc#978160)

  - CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)

  - CVE-2016-2538: Fixed potential OOB access in USB net
    device emulation (bsc#967969)

  - CVE-2016-2841: Fixed OOB access / hang in ne2000
    emulation (bsc#969350)

  - CVE-2016-2858: Avoid potential DOS when using QEMU
    pseudo random number generator (bsc#970036)

  - CVE-2016-2857: Fixed OOB access when processing IP
    checksums (bsc#970037)

  - CVE-2016-4001: Fixed OOB access in Stellaris enet
    emulated nic (bsc#975128)

  - CVE-2016-4002: Fixed OOB access in MIPSnet emulated
    controller (bsc#975136)

  - CVE-2016-4020: Fixed possible host data leakage to guest
    from TPR access (bsc#975700)

  - CVE-2016-2197: Prevent AHCI NULL pointer dereference
    when using FIS CLB engine (bsc#964411)

  - CVE-2015-5745: Buffer overflow in virtio-serial
    (bsc#940929).

  - CVE-2015-7549: PCI NULL pointer dereferences
    (bsc#958917).

  - CVE-2015-8504: VNC floating point exception
    (bsc#958491).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulting in DoS (bsc#959005).

  - CVE-2015-8567: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8568: A guest repeatedly activating a vmxnet3
    device can leak host memory (bsc#959386).

  - CVE-2015-8613: Wrong sized memset in megasas command
    handler (bsc#961358).

  - CVE-2015-8619: Potential DoS for long HMP sendkey
    command argument (bsc#960334).

  - CVE-2015-8743: OOB memory access in ne2000 ioport r/w
    functions (bsc#960725).

  - CVE-2015-8744: Incorrect l2 header validation could have
    lead to a crash via assert(2) call (bsc#960835).

  - CVE-2015-8745: Reading IMR registers could have lead to
    a crash via assert(2) call (bsc#960708).

  - CVE-2016-1568: AHCI use-after-free in aio port commands
    (bsc#961332).

  - CVE-2016-1714: Potential OOB memory access in processing
    firmware configuration (bsc#961691).

  - CVE-2016-1922: NULL pointer dereference when processing
    hmp i/o command (bsc#962320).

  - CVE-2016-1981: Potential DoS (infinite loop) in e1000
    device emulation by malicious privileged user within
    guest (bsc#963782).

  - CVE-2016-2198: Malicious privileged guest user were able
    to cause DoS by writing to read-only EHCI capabilities
    registers (bsc#964413).

This non-security issue was fixed

  - bsc#886378: qemu truncates vhd images in virt-rescue

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1714.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2857.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3712.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4037.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4952.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161703-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd012f9d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-1007=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-1007=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-debugsource-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-lang-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-kvm-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-debugsource-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-kvm-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.3.1-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
