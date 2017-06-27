#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1105-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83633);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2013-4299", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-1739", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-5077");
  script_bugtraq_id(63183, 66441, 66591, 66678, 66779, 67309, 67321, 67699, 68048, 68126, 68162, 68163, 68164, 68170, 68224, 68411, 68881);
  script_osvdb_id(105302, 106969, 107819, 108293, 108386, 108389, 108390, 108451, 108473, 108754, 109512);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2014:1105-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 11 SP2 LTSS received a roll up update
to fix several security and non-security issues.

The following security issues have been fixed :

  - CVE-2014-0055: The get_rx_bufs function in
    drivers/vhost/net.c in the vhost-net subsystem in the
    Linux kernel package before 2.6.32-431.11.2 on Red Hat
    Enterprise Linux (RHEL) 6 does not properly handle
    vhost_get_vq_desc errors, which allows guest OS users to
    cause a denial of service (host OS crash) via
    unspecified vectors. (bnc#870173)

  - CVE-2014-0077: drivers/vhost/net.c in the Linux kernel
    before 3.13.10, when mergeable buffers are disabled,
    does not properly validate packet lengths, which allows
    guest OS users to cause a denial of service (memory
    corruption and host OS crash) or possibly gain
    privileges on the host OS via crafted packets, related
    to the handle_rx and get_rx_bufs functions. (bnc#870576)

  - CVE-2014-1739: The media_device_enum_entities function
    in drivers/media/media-device.c in the Linux kernel
    before 3.14.6 does not initialize a certain data
    structure, which allows local users to obtain sensitive
    information from kernel memory by leveraging /dev/media0
    read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call.
    (bnc#882804)

  - CVE-2014-2706: Race condition in the mac80211 subsystem
    in the Linux kernel before 3.13.7 allows remote
    attackers to cause a denial of service (system crash)
    via network traffic that improperly interacts with the
    WLAN_STA_PS_STA state (aka power-save mode), related to
    sta_info.c and tx.c. (bnc#871797)

  - CVE-2014-2851: Integer overflow in the ping_init_sock
    function in net/ipv4/ping.c in the Linux kernel through
    3.14.1 allows local users to cause a denial of service
    (use-after-free and system crash) or possibly gain
    privileges via a crafted application that leverages an
    improperly managed reference counter. (bnc#873374)

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

  - CVE-2014-5077: The sctp_assoc_update function in
    net/sctp/associola.c in the Linux kernel through 3.15.8,
    when SCTP authentication is enabled, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and OOPS) by starting to establish an
    association between two endpoints immediately after an
    exchange of INIT and INIT ACK chunks to establish an
    earlier association between these endpoints in the
    opposite direction. (bnc#889173)

  - CVE-2013-4299: Interpretation conflict in
    drivers/md/dm-snap-persistent.c in the Linux kernel
    through 3.11.6 allows remote authenticated users to
    obtain sensitive information or modify data via a
    crafted mapping to a snapshot block device. (bnc#846404)

The following bugs have been fixed :

  - pagecachelimit: reduce lru_lock contention for heavy
    parallel reclaim (bnc#878509, bnc#864464).

  - pagecachelimit: reduce lru_lock contention for heavy
    parallel reclaim kabi fixup (bnc#878509, bnc#864464).

  - ACPI / PAD: call schedule() when need_resched() is true
    (bnc#866911).

  - kabi: Fix breakage due to addition of user_ctl_lock
    (bnc#883795).

  - cpuset: Fix memory allocator deadlock (bnc#876590).

  - tcp: allow to disable cwnd moderation in TCP_CA_Loss
    state (bnc#879921).

  - tcp: adapt selected parts of RFC 5682 and PRR logic
    (bnc#879921).

  - vlan: more careful checksum features handling
    (bnc#872634).

  - bonding: fix vlan_features computing (bnc#872634).

  - NFSv4: Minor cleanups for nfs4_handle_exception and
    nfs4_async_handle_error (bnc#889324).

  - NFS: Do not lose sockets when nfsd shutdown races with
    connection timeout (bnc#871854).

  - reiserfs: call truncate_setsize under tailpack mutex
    (bnc#878115).

  - reiserfs: drop vmtruncate (bnc#878115).

  - megaraid_sas: mask off flags in ioctl path (bnc#886474).

  - block: fix race between request completion and timeout
    handling (bnc#881051).

  - drivers/rtc/interface.c: fix infinite loop in
    initializing the alarm (bnc#871676).

  - xfrm: check peer pointer for null before calling
    inet_putpeer() (bnc#877775).

  - supported.conf: Add firewire/nosy as supported. This
    driver is the replacement for the ieee1394/pcilynx
    driver, which was supported.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=1bdb6880fea42253a50653414920422e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfd31720"
  );
  # http://download.suse.com/patch/finder/?keywords=218ba78474014b91211cb482f9ce7a3a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad2400ab"
  );
  # http://download.suse.com/patch/finder/?keywords=3fe24f0ad52cbb8be44e129fa1f0497a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae0fa787"
  );
  # http://download.suse.com/patch/finder/?keywords=41c4d735ff2c6886df2aa7dfcce0107b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?accb227f"
  );
  # http://download.suse.com/patch/finder/?keywords=4d4557738b3fb3592211aa4ebb60e887
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9ff4392"
  );
  # http://download.suse.com/patch/finder/?keywords=4de705ad690dac2ee164aea48d16db9a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90630f72"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2706.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2851.html"
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
    value:"http://support.novell.com/security/cve/CVE-2014-5077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/864464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/866911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/870173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/870576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/871676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/871797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/871854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/872634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/873374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/876590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/877257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/877775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/878115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/878509"
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
    value:"https://bugzilla.novell.com/882804"
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
    value:"https://bugzilla.novell.com/885422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/885725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/886474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/889173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/889324"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141105-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3e6f666"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-kernel-9630 slessp2-kernel-9631
slessp2-kernel-9632

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_06_3.0.101_0.7.23-0.5.30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
