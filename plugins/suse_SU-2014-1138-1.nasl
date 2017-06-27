#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1138-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83640);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2013-1860", "CVE-2013-4162", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2014-0203", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5077");
  script_bugtraq_id(58510, 61411, 64739, 64741, 64742, 64743, 64744, 64746, 67309, 67321, 67699, 68125, 68126, 68162, 68163, 68164, 68170, 68224, 68411, 68683, 68768, 68881);
  script_osvdb_id(106969, 108293, 108386, 108389, 108390, 108451, 108473, 108754, 109277, 109512);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2014:1138-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 11 SP1 LTSS received a roll up update
to fix several security and non-security issues.

The following security issues have been fixed :

  - CVE-2013-1860: Heap-based buffer overflow in the
    wdm_in_callback function in drivers/usb/class/cdc-wdm.c
    in the Linux kernel before 3.8.4 allows physically
    proximate attackers to cause a denial of service (system
    crash) or possibly execute arbitrary code via a crafted
    cdc-wdm USB device. (bnc#806431)

  - CVE-2013-4162: The udp_v6_push_pending_frames function
    in net/ipv6/udp.c in the IPv6 implementation in the
    Linux kernel through 3.10.3 makes an incorrect function
    call for pending data, which allows local users to cause
    a denial of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call. (bnc#831058)

  - CVE-2014-0203: The __do_follow_link function in
    fs/namei.c in the Linux kernel before 2.6.33 does not
    properly handle the last pathname component during use
    of certain filesystems, which allows local users to
    cause a denial of service (incorrect free operations and
    system crash) via an open system call. (bnc#883526)

  - CVE-2014-3144: The (1) BPF_S_ANC_NLATTR and (2)
    BPF_S_ANC_NLATTR_NEST extension implementations in the
    sk_run_filter function in net/core/filter.c in the Linux
    kernel through 3.14.3 do not check whether a certain
    length value is sufficiently large, which allows local
    users to cause a denial of service (integer underflow
    and system crash) via crafted BPF instructions. NOTE:
    the affected code was moved to the __skb_get_nlattr and
    __skb_get_nlattr_nest functions before the vulnerability
    was announced. (bnc#877257)

  - CVE-2014-3145: The BPF_S_ANC_NLATTR_NEST extension
    implementation in the sk_run_filter function in
    net/core/filter.c in the Linux kernel through 3.14.3
    uses the reverse order in a certain subtraction, which
    allows local users to cause a denial of service
    (over-read and system crash) via crafted BPF
    instructions. NOTE: the affected code was moved to the
    __skb_get_nlattr_nest function before the vulnerability
    was announced. (bnc#877257)

  - CVE-2014-3917: kernel/auditsc.c in the Linux kernel
    through 3.14.5, when CONFIG_AUDITSYSCALL is enabled with
    certain syscall rules, allows local users to obtain
    potentially sensitive single-bit values from kernel
    memory or cause a denial of service (OOPS) via a large
    value of a syscall number. (bnc#880484)

  - CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux
    kernel through 3.15.1 on 32-bit x86 platforms, when
    syscall auditing is enabled and the sep CPU feature flag
    is set, allows local users to cause a denial of service
    (OOPS and system crash) via an invalid syscall number,
    as demonstrated by number 1000. (bnc#883724)

  - CVE-2014-4652: Race condition in the tlv handler
    functionality in the snd_ctl_elem_user_tlv function in
    sound/core/control.c in the ALSA control implementation
    in the Linux kernel before 3.15.2 allows local users to
    obtain sensitive information from kernel memory by
    leveraging /dev/snd/controlCX access. (bnc#883795)

  - CVE-2014-4653: sound/core/control.c in the ALSA control
    implementation in the Linux kernel before 3.15.2 does
    not ensure possession of a read/write lock, which allows
    local users to cause a denial of service
    (use-after-free) and obtain sensitive information from
    kernel memory by leveraging /dev/snd/controlCX access.
    (bnc#883795)

  - CVE-2014-4654: The snd_ctl_elem_add function in
    sound/core/control.c in the ALSA control implementation
    in the Linux kernel before 3.15.2 does not check
    authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands,
    which allows local users to remove kernel controls and
    cause a denial of service (use-after-free and system
    crash) by leveraging /dev/snd/controlCX access for an
    ioctl call. (bnc#883795)

  - CVE-2014-4655: The snd_ctl_elem_add function in
    sound/core/control.c in the ALSA control implementation
    in the Linux kernel before 3.15.2 does not properly
    maintain the user_ctl_count value, which allows local
    users to cause a denial of service (integer overflow and
    limit bypass) by leveraging /dev/snd/controlCX access
    for a large number of SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl
    calls. (bnc#883795)

  - CVE-2014-4656: Multiple integer overflows in
    sound/core/control.c in the ALSA control implementation
    in the Linux kernel before 3.15.2 allow local users to
    cause a denial of service by leveraging
    /dev/snd/controlCX access, related to (1) index values
    in the snd_ctl_add function and (2) numid values in the
    snd_ctl_remove_numid_conflict function. (bnc#883795)

  - CVE-2014-4667: The sctp_association_free function in
    net/sctp/associola.c in the Linux kernel before 3.15.2
    does not properly manage a certain backlog value, which
    allows remote attackers to cause a denial of service
    (socket outage) via a crafted SCTP packet. (bnc#885422)

  - CVE-2014-4699: The Linux kernel before 3.15.4 on Intel
    processors does not properly restrict use of a
    non-canonical value for the saved RIP address in the
    case of a system call that does not use IRET, which
    allows local users to leverage a race condition and gain
    privileges, or cause a denial of service (double fault),
    via a crafted application that makes ptrace and fork
    system calls. (bnc#885725)

  - CVE-2014-4943: The PPPoL2TP feature in
    net/l2tp/l2tp_ppp.c in the Linux kernel through 3.15.6
    allows local users to gain privileges by leveraging
    data-structure differences between an l2tp socket and an
    inet socket. (bnc#887082)

  - CVE-2014-5077: The sctp_assoc_update function in
    net/sctp/associola.c in the Linux kernel through 3.15.8,
    when SCTP authentication is enabled, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and OOPS) by starting to establish an
    association between two endpoints immediately after an
    exchange of INIT and INIT ACK chunks to establish an
    earlier association between these endpoints in the
    opposite direction. (bnc#889173)

  - CVE-2013-7266: The mISDN_sock_recvmsg function in
    drivers/isdn/mISDN/socket.c in the Linux kernel before
    3.12.4 does not ensure that a certain length value is
    consistent with the size of an associated data
    structure, which allows local users to obtain sensitive
    information from kernel memory via a (1) recvfrom, (2)
    recvmmsg, or (3) recvmsg system call. (bnc#854722)

  - CVE-2013-7267: The atalk_recvmsg function in
    net/appletalk/ddp.c in the Linux kernel before 3.12.4
    updates a certain length value without ensuring that an
    associated data structure has been initialized, which
    allows local users to obtain sensitive information from
    kernel memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call. (bnc#854722)

  - CVE-2013-7268: The ipx_recvmsg function in
    net/ipx/af_ipx.c in the Linux kernel before 3.12.4
    updates a certain length value without ensuring that an
    associated data structure has been initialized, which
    allows local users to obtain sensitive information from
    kernel memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call. (bnc#854722)

  - CVE-2013-7269: The nr_recvmsg function in
    net/netrom/af_netrom.c in the Linux kernel before 3.12.4
    updates a certain length value without ensuring that an
    associated data structure has been initialized, which
    allows local users to obtain sensitive information from
    kernel memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call. (bnc#854722)

  - CVE-2013-7270: The packet_recvmsg function in
    net/packet/af_packet.c in the Linux kernel before 3.12.4
    updates a certain length value before ensuring that an
    associated data structure has been initialized, which
    allows local users to obtain sensitive information from
    kernel memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call. (bnc#854722)

  - CVE-2013-7271: The x25_recvmsg function in
    net/x25/af_x25.c in the Linux kernel before 3.12.4
    updates a certain length value without ensuring that an
    associated data structure has been initialized, which
    allows local users to obtain sensitive information from
    kernel memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call. (bnc#854722)

The following bugs have been fixed :

  - mac80211: Fix AP powersave TX vs. wakeup race
    (bnc#871797).

  - tcp: Allow to disable cwnd moderation in TCP_CA_Loss
    state (bnc#879921).

  - tcp: Adapt selected parts of RFC 5682 and PRR logic
    (bnc#879921).

  - flock: Fix allocation and BKL (bnc#882809).

  - sunrpc: Close a rare race in xs_tcp_setup_socket
    (bnc#794824, bnc#884530).

  - isofs: Fix unbounded recursion when processing relocated
    directories (bnc#892490).

  - bonding: Fix a race condition on cleanup in
    bond_send_unsolicited_na() (bnc#856756).

  - block: Fix race between request completion and timeout
    handling (bnc#881051).

  - Fix kABI breakage due to addition of user_ctl_lock
    (bnc#883795).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=33223d7de0d6fcaf9f12c0175a720ae1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3c69850"
  );
  # http://download.suse.com/patch/finder/?keywords=753dcd87154cfcee28dc062d0421697d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfeac487"
  );
  # http://download.suse.com/patch/finder/?keywords=ad20790f90bee656575f760123b63fe2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3559b23"
  );
  # http://download.suse.com/patch/finder/?keywords=bb89429b2b6bbf8e51a9b446b5a9f825
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?549c16fd"
  );
  # http://download.suse.com/patch/finder/?keywords=cc2185e1b7bb5f72a49d967c7dcf07ee
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?343b302c"
  );
  # http://download.suse.com/patch/finder/?keywords=f3d32743e8c31acee5f4fb836923cc28
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97158f81"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7266.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7267.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7269.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4667.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/794824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/856756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/871797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/877257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/879921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/880484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/881051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/882809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/883526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/883724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/883795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/884530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/885422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/885725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/887082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/889173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/892490"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141138-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3197a953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-kernel-9658 slessp1-kernel-9660
slessp1-kernel-9667

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-pae-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"kernel-default-man-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-source-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-syms-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-base-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-devel-2.6.32.59-0.15.2")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_16_2.6.32.59_0.15-0.5.26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
