#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0647-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97657);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/20 15:44:33 $");

  script_cve_id("CVE-2014-8106", "CVE-2016-10155", "CVE-2016-9101", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5579", "CVE-2017-5856", "CVE-2017-5898", "CVE-2017-5973");
  script_bugtraq_id(71477);
  script_osvdb_id(115343, 115344, 146392, 148129, 148291, 148375, 148394, 150692, 150976, 151241, 151338, 151566, 151974, 152349);
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2017:0647-1)");
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

  - CVE-2017-5973: A infinite loop while doing control
    transfer in xhci_kick_epctx allowed privileged user
    inside the guest to crash the host process resulting in
    DoS (bsc#1025188)

  - CVE-2016-10155: The virtual hardware watchdog
    'wdt_i6300esb' was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1024183)

  - CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the
    bitblit copy routine cirrus_bitblt_cputovideo failed to
    check the memory region, allowing for an out-of-bounds
    write that allows for privilege escalation (bsc#1024834)

  - CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a memory leakage
    issue allowing a privileged user to leak host memory
    resulting in DoS (bsc#1024186)

  - CVE-2017-5898: The CCID Card device emulator support was
    vulnerable to an integer overflow flaw allowing a
    privileged user to crash the Qemu process on the host
    resulting in DoS (bsc#1024307)

  - CVE-2017-2615: An error in the bitblt copy operation
    could have allowed a malicious guest administrator to
    cause an out of bounds memory access, possibly leading
    to information disclosure or privilege escalation
    (bsc#1023004)

  - CVE-2014-8106: A heap-based buffer overflow in the
    Cirrus VGA emulator allowed local guest users to execute
    arbitrary code via vectors related to blit regions
    (bsc#907805)

  - CVE-2017-5579: The 16550A UART serial device emulation
    support was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1022627)

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014490)

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014507)

  - CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1015169)

  - CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1015169)

  - CVE-2016-9101: A memory leak in hw/net/eepro100.c
    allowed local guest OS administrators to cause a denial
    of service (memory consumption and QEMU process crash)
    by repeatedly unplugging an i8255x (PRO100) NIC device
    (bsc#1013668)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013657)

  - A malicious guest could have, by frequently rebooting
    over extended periods of time, run the host system out
    of memory, resulting in a Denial of Service (DoS)
    (bsc#1022871) These non-security issues were fixed :

  - bsc#1000195: Prevent panic on CPU0 while booting on SLES
    11 SP3

  - bsc#1002496: Added support for reloading clvm in
    block-dmmd block-dmmd

  - bsc#987002: Prevent crash of domU' after they were
    migrated from SP3 HV to SP4

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9907.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2620.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5579.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5856.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5973.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170647-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c47c199b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-xen-13019=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-xen-13019=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-xen-13019=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_14_3.0.101_94-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-doc-html-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-pae-4.4.4_14_3.0.101_94-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-default-4.4.4_14_3.0.101_94-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-libs-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-tools-domU-4.4.4_14-51.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-pae-4.4.4_14_3.0.101_94-51.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
