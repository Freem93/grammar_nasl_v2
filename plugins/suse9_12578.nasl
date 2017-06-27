#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44654);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-1883", "CVE-2009-2903", "CVE-2009-3080", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3889", "CVE-2009-4005", "CVE-2009-4536", "CVE-2010-0007");

  script_name(english:"SuSE9 Security Update : the Linux kernel (YOU Patch Number 12578)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various security issues and some bugs in the SUSE
Linux Enterprise 9 kernel.

  - The collect_rx_frame function in
    drivers/isdn/hisax/hfc_usb.c in the Linux kernel allows
    attackers to have an unspecified impact via a crafted
    HDLC packet that arrives over ISDN and triggers a buffer
    under-read. (CVE-2009-4005)

  - Array index error in the gdth_read_event function in
    drivers/scsi/gdth.c in the Linux kernel allows local
    users to cause a denial of service or possibly gain
    privileges via a negative event index in an IOCTL
    request. (CVE-2009-3080)

  - Missing CAP_NET_ADMIN checks in the ebtables netfilter
    code might have allowed local attackers to modify bridge
    firewall settings. (CVE-2010-0007)

  - drivers/net/e1000/e1000_main.c in the e1000 driver in
    the Linux kernel handles Ethernet frames that exceed the
    MTU by processing certain trailing payload data as if it
    were a complete frame, which allows remote attackers to
    bypass packet filters via a large packet with a crafted
    payload. (CVE-2009-4536)

  - The dbg_lvl file for the megaraid_sas driver in the
    Linux kernel has world-writable permissions, which
    allows local users to change the (1) behavior and (2)
    logging level of the driver by modifying this file.
    (CVE-2009-3889)

  - The z90crypt_unlocked_ioctl function in the z90crypt
    driver in the Linux kernel does not perform a capability
    check for the Z90QUIESCE operation, which allows local
    users to leverage euid 0 privileges to force a driver
    outage. (CVE-2009-1883)

  - Memory leak in the appletalk subsystem in the Linux
    kernel, when the appletalk and ipddp modules are loaded
    but the ipddp'N' device is not found, allows remote
    attackers to cause a denial of service (memory
    consumption) via IP-DDP datagrams. (CVE-2009-2903)

  - net/1/af_unix.c in the Linux kernel allows local users
    to cause a denial of service (system hang) by creating
    an abstract-namespace AF_UNIX listening socket,
    performing a shutdown operation on this socket, and then
    performing a series of connect operations to this
    socket. (CVE-2009-3621)

  - The ATI Rage 128 (aka r128) driver in the Linux kernel
    does not properly verify Concurrent Command Engine (CCE)
    state initialization, which allows local users to cause
    a denial of service (NULL pointer dereference and system
    crash) or possibly gain privileges via unspecified ioctl
    calls. (CVE-2009-3620)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3620.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0007.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12578.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-bigsmp-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-debug-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-default-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-smp-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-source-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-syms-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-um-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xen-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xenpae-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-install-initrd-1.0-48.35")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-kernel-2.6.5-7.322")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"xen-kmp-3.0.4_2.6.5_7.322-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
