#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1785-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93180);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-3689", "CVE-2014-9718", "CVE-2015-3214", "CVE-2015-5239", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-5745", "CVE-2015-6855", "CVE-2015-7295", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441");
  script_bugtraq_id(69654, 70997, 73316, 75273);
  script_osvdb_id(111030, 114397, 120289, 123468, 125847, 127119, 127378, 127493, 127494, 127769, 131399, 131668, 131793, 132136, 132210, 132257, 132466, 132467, 132759, 132798, 133524, 133811, 134888, 135279, 135305, 135338, 136948, 136949, 137159, 137352, 138373, 138374, 138741, 138742);

  script_name(english:"SUSE SLES11 Security Update : kvm (SUSE-SU-2016:1785-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kvm was updated to fix 33 security issues.

These security issues were fixed :

  - CVE-2016-4439: Avoid OOB access in 53C9X emulation
    (bsc#980711)

  - CVE-2016-4441: Avoid OOB access in 53C9X emulation
    (bsc#980723)

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

  - CVE-2015-3214: Fixed OOB read in i8254 PIC (bsc#934069)

  - CVE-2014-9718: Fixed the handling of malformed or short
    ide PRDTs to avoid any opportunity for guest to cause
    DoS by abusing that interface (bsc#928393)

  - CVE-2014-3689: Fixed insufficient parameter validation
    in rectangle functions (bsc#901508)

  - CVE-2014-3615: The VGA emulator in QEMU allowed local
    guest users to read host memory by setting the display
    to a high resolution (bsc#895528).

  - CVE-2015-5239: Integer overflow in vnc_client_read() and
    protocol_client_msg() (bsc#944463).

  - CVE-2015-5278: Infinite loop in ne2000_receive()
    function (bsc#945989).

  - CVE-2015-5279: Heap-based buffer overflow in the
    ne2000_receive function in hw/net/ne2000.c in QEMU
    allowed guest OS users to cause a denial of service
    (instance crash) or possibly execute arbitrary code via
    vectors related to receiving packets (bsc#945987).

  - CVE-2015-5745: Buffer overflow in virtio-serial
    (bsc#940929).

  - CVE-2015-6855: hw/ide/core.c in QEMU did not properly
    restrict the commands accepted by an ATAPI device, which
    allowed guest users to cause a denial of service or
    possibly have unspecified other impact via certain IDE
    commands, as demonstrated by a WIN_READ_NATIVE_MAX
    command to an empty drive, which triggers a
    divide-by-zero error and instance crash (bsc#945404).

  - CVE-2015-7295: hw/virtio/virtio.c in the Virtual Network
    Device (virtio-net) support in QEMU, when big or
    mergeable receive buffers are not supported, allowed
    remote attackers to cause a denial of service (guest
    network consumption) via a flood of jumbo frames on the
    (1) tuntap or (2) macvtap interface (bsc#947159).

  - CVE-2015-7549: PCI NULL pointer dereferences
    (bsc#958917).

  - CVE-2015-8504: VNC floating point exception
    (bsc#958491).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulting in DoS (bsc#959005).

  - CVE-2015-8613: Wrong sized memset in megasas command
    handler (bsc#961358).

  - CVE-2015-8619: Potential DoS for long HMP sendkey
    command argument (bsc#960334).

  - CVE-2015-8743: OOB memory access in ne2000 ioport r/w
    functions (bsc#960725).

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

This non-security issue was fixed :

  - Fix case of IDE interface needing busy status set before
    flush (bsc#936132)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947159"
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
    value:"https://bugzilla.suse.com/960334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960725"
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
    value:"https://bugzilla.suse.com/964413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967969"
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
    value:"https://www.suse.com/security/cve/CVE-2014-3615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5239.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5279.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7295.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161785-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d049621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kvm-12645=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"kvm-1.4.2-44.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
