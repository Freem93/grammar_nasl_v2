#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59155);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2010-1173", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4342", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4655", "CVE-2010-4668", "CVE-2011-0521", "CVE-2011-0710", "CVE-2011-0711");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7384)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP3 kernel fixes
several security issues and bugs.

The following security issues were fixed :

  - A memory leak in the ethtool ioctl was fixed that could
    disclose kernel memory to local attackers with
    CAP_NET_ADMIN privileges. (CVE-2010-4655)

  - The dvb_ca_ioctl function in
    drivers/media/dvb/ttpci/av7110_ca.c in the Linux kernel
    did not check the sign of a certain integer field, which
    allowed local users to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via a negative value. (CVE-2011-0521)

  - The ax25_getname function in net/ax25/af_ax25.c in the
    Linux kernel did not initialize a certain structure,
    which allowed local users to obtain potentially
    sensitive information from kernel stack memory by
    reading a copy of this structure. (CVE-2010-3875)

  - net/packet/af_packet.c in the Linux kernel did not
    properly initialize certain structure members, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory by leveraging the
    CAP_NET_RAW capability to read copies of the applicable
    structures. (CVE-2010-3876)

  - The get_name function in net/tipc/socket.c in the Linux
    kernel did not initialize a certain structure, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory by reading a copy
    of this structure. (CVE-2010-3877)

  - A stack memory information leak in the xfs FSGEOMETRY_V1
    ioctl was fixed. (CVE-2011-0711)

  - The task_show_regs function in arch/s390/kernel/traps.c
    in the Linux kernel on the s390 platform allowed local
    users to obtain the values of the registers of an
    arbitrary process by reading a status file under /proc/.
    (CVE-2011-0710)

  - The sctp_process_unk_param function in
    net/sctp/sm_make_chunk.c in the Linux kernel, when SCTP
    is enabled, allowed remote attackers to cause a denial
    of service (system crash) via an SCTPChunkInit packet
    containing multiple invalid parameters that require a
    large amount of error data. (CVE-2010-1173)

  - The uart_get_count function in
    drivers/serial/serial_core.c in the Linux kernel did not
    properly initialize a certain structure member, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT
    ioctl call. (CVE-2010-4075)

  - The rs_ioctl function in drivers/char/amiserial.c in the
    Linux kernel did not properly initialize a certain
    structure member, which allowed local users to obtain
    potentially sensitive information from kernel stack
    memory via a TIOCGICOUNT ioctl call. (CVE-2010-4076)

  - The ntty_ioctl_tiocgicount function in
    drivers/char/nozomi.c in the Linux kernel did not
    properly initialize a certain structure member, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT
    ioctl call. (CVE-2010-4077)

  - The load_mixer_volumes function in sound/oss/soundcard.c
    in the OSS sound subsystem in the Linux kernel
    incorrectly expected that a certain name field ends with
    a '0' character, which allowed local users to conduct
    buffer overflow attacks and gain privileges, or possibly
    obtain sensitive information from kernel memory, via a
    SOUND_MIXER_SETLEVELS ioctl call. (CVE-2010-4527)

  - Race condition in the __exit_signal function in
    kernel/exit.c in the Linux kernel allowed local users to
    cause a denial of service via vectors related to
    multithreaded exec, the use of a thread group leader in
    kernel/posix-cpu-timers.c, and the selection of a new
    thread group leader in the de_thread function in
    fs/exec.c. (CVE-2010-4248)

  - The blk_rq_map_user_iov function in block/blk-map.c in
    the Linux kernel allowed local users to cause a denial
    of service (panic) via a zero-length I/O request in a
    device ioctl to a SCSI device, related to an unaligned
    map. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2010-4163. (CVE-2010-4668)

  - The hci_uart_tty_open function in the HCI UART driver
    (drivers/bluetooth/hci_ldisc.c) in the Linux kernel did
    not verify whether the tty has a write operation, which
    allowed local users to cause a denial of service (NULL
    pointer dereference) via vectors related to the
    Bluetooth driver. (CVE-2010-4242)

  - Integer underflow in the irda_getsockopt function in
    net/irda/af_irda.c in the Linux kernel on platforms
    other than x86 allowed local users to obtain potentially
    sensitive information from kernel heap memory via an
    IRLMP_ENUMDEVICES getsockopt call. (CVE-2010-4529)

  - The aun_incoming function in net/econet/af_econet.c in
    the Linux kernel, when Econet is enabled, allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and OOPS) by sending an Acorn Universal
    Networking (AUN) packet over UDP. (CVE-2010-4342)

  - Race condition in the sctp_icmp_proto_unreachable
    function in net/sctp/input.c in Linux kernel allowed
    remote attackers to cause a denial of service (panic)
    via an ICMP unreachable message to a socket that is
    already locked by a user, which causes the socket to be
    freed and triggers list corruption, related to the
    sctp_wait_for_connect function. (CVE-2010-4526)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3875.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4668.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0711.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7384.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.77.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.77.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
