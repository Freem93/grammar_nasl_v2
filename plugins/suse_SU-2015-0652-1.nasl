#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0652-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83708);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2010-5313", "CVE-2012-6657", "CVE-2013-4299", "CVE-2013-7263", "CVE-2014-0181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-8160", "CVE-2014-8709", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585");
  script_bugtraq_id(63183, 64686, 67034, 69768, 69781, 69803, 70766, 70768, 70883, 70965, 71078, 71081, 71363, 71717, 71883, 71990, 72061);
  script_osvdb_id(100422, 106174, 110567, 110568, 110569, 110570, 110571, 110572, 110732, 113724, 113726, 113727, 114393, 114575, 114689, 116075, 116767, 116910, 117131);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2015:0652-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 1 LTSS kernel was updated to
fix security issues on kernels on the x86_64 architecture.

The following security bugs have been fixed :

  - CVE-2013-4299: Interpretation conflict in
    drivers/md/dm-snap-persistent.c in the Linux kernel
    through 3.11.6 allowed remote authenticated users to
    obtain sensitive information or modify data via a
    crafted mapping to a snapshot block device (bnc#846404).

  - CVE-2014-8160: SCTP firewalling failed until the SCTP
    module was loaded (bnc#913059).

  - CVE-2014-9584: The parse_rock_ridge_inode_internal
    function in fs/isofs/rock.c in the Linux kernel before
    3.18.2 did not validate a length value in the Extensions
    Reference (ER) System Use Field, which allowed local
    users to obtain sensitive information from kernel memory
    via a crafted iso9660 image (bnc#912654).

  - CVE-2014-9585: The vdso_addr function in
    arch/x86/vdso/vma.c in the Linux kernel through 3.18.2
    did not properly choose memory locations for the vDSO
    area, which made it easier for local users to bypass the
    ASLR protection mechanism by guessing a location at the
    end of a PMD (bnc#912705).

  - CVE-2014-9420: The rock_continue function in
    fs/isofs/rock.c in the Linux kernel through 3.18.1 did
    not restrict the number of Rock Ridge continuation
    entries, which allowed local users to cause a denial of
    service (infinite loop, and system crash or hang) via a
    crafted iso9660 image (bnc#911325).

  - CVE-2014-0181: The Netlink implementation in the Linux
    kernel through 3.14.1 did not provide a mechanism for
    authorizing socket operations based on the opener of a
    socket, which allowed local users to bypass intended
    access restrictions and modify network configurations by
    using a Netlink socket for the (1) stdout or (2) stderr
    of a setuid program (bnc#875051).

  - CVE-2010-5313: Race condition in arch/x86/kvm/x86.c in
    the Linux kernel before 2.6.38 allowed L2 guest OS users
    to cause a denial of service (L1 guest OS crash) via a
    crafted instruction that triggers an L2 emulation
    failure report, a similar issue to CVE-2014-7842
    (bnc#907822).

  - CVE-2014-7842: Race condition in arch/x86/kvm/x86.c in
    the Linux kernel before 3.17.4 allowed guest OS users to
    cause a denial of service (guest OS crash) via a crafted
    application that performs an MMIO transaction or a PIO
    transaction to trigger a guest userspace emulation error
    report, a similar issue to CVE-2010-5313 (bnc#905312).

  - CVE-2014-3688: The SCTP implementation in the Linux
    kernel before 3.17.4 allowed remote attackers to cause a
    denial of service (memory consumption) by triggering a
    large number of chunks in an associations output queue,
    as demonstrated by ASCONF probes, related to
    net/sctp/inqueue.c and net/sctp/sm_statefuns.c
    (bnc#902351).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function
    in net/sctp/associola.c in the SCTP implementation in
    the Linux kernel through 3.17.2 allowed remote attackers
    to cause a denial of service (panic) via duplicate
    ASCONF chunks that trigger an incorrect uncork within
    the side-effect interpreter (bnc#902349).

  - CVE-2014-3673: The SCTP implementation in the Linux
    kernel through 3.17.2 allowed remote attackers to cause
    a denial of service (system crash) via a malformed
    ASCONF chunk, related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c (bnc#902346).

  - CVE-2014-7841: The sctp_process_param function in
    net/sctp/sm_make_chunk.c in the SCTP implementation in
    the Linux kernel before 3.17.4, when ASCONF is used,
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) via a
    malformed INIT chunk (bnc#905100).

  - CVE-2014-8709: The ieee80211_fragment function in
    net/mac80211/tx.c in the Linux kernel before 3.13.5 did
    not properly maintain a certain tail pointer, which
    allowed remote attackers to obtain sensitive cleartext
    information by reading packets (bnc#904700).

  - CVE-2013-7263: The Linux kernel before 3.12.4 updated
    certain length values before ensuring that associated
    data structures have been initialized, which allowed
    local users to obtain sensitive information from kernel
    stack memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call, related to net/ipv4/ping.c,
    net/ipv4/raw.c, net/ipv4/udp.c, net/ipv6/raw.c, and
    net/ipv6/udp.c (bnc#857643).

  - CVE-2012-6657: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel before 3.5.7 did not
    ensure that a keepalive action is associated with a
    stream socket, which allowed local users to cause a
    denial of service (system crash) by leveraging the
    ability to create a raw socket (bnc#896779).

  - CVE-2014-3185: Multiple buffer overflows in the
    command_port_read_callback function in
    drivers/usb/serial/whiteheat.c in the Whiteheat USB
    Serial Driver in the Linux kernel before 3.16.2 allowed
    physically proximate attackers to execute arbitrary code
    or cause a denial of service (memory corruption and
    system crash) via a crafted device that provides a large
    amount of (1) EHCI or (2) XHCI data associated with a
    bulk response (bnc#896391).

  - CVE-2014-3184: The report_fixup functions in the HID
    subsystem in the Linux kernel before 3.16.2 might allow
    physically proximate attackers to cause a denial of
    service (out-of-bounds write) via a crafted device that
    provides a small report descriptor, related to (1)
    drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
    drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c,
    (5) drivers/hid/hid-petalynx.c, and (6)
    drivers/hid/hid-sunplus.c (bnc#896390).

The following non-security bugs have been fixed :

  - KVM: SVM: Make Use of the generic guest-mode functions
    (bnc#907822).

  - KVM: inject #UD if instruction emulation fails and exit
    to userspace (bnc#907822).

  - block: Fix bogus partition statistics reports
    (bnc#885077 bnc#891211).

  - block: skip request queue cleanup if no elevator is
    assigned (bnc#899338).

  - isofs: Fix unchecked printing of ER records.

  - Re-enable nested-spinlocks-backport patch for xen
    (bnc#908870).

  - time, ntp: Do not update time_state in middle of leap
    second (bnc#912916).

  - timekeeping: Avoid possible deadlock from
    clock_was_set_delayed (bnc#771619, bnc#915335).

  - udf: Check component length before reading it.

  - udf: Check path length when reading symlink.

  - udf: Verify i_size when loading inode.

  - udf: Verify symlink size before loading it.

  - vt: prevent race between modifying and reading unicode
    map (bnc#915826).

  - writeback: Do not sync data dirtied after sync start
    (bnc#833820).

  - xfs: Avoid blocking on inode flush in background inode
    reclaim (bnc#892235).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/771619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/833820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/846404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/875051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/885077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/891211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/892235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915826"
  );
  # https://download.suse.com/patch/finder/?keywords=01007b3b761286f24a9cd5a7197794e2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?859a6bb5"
  );
  # https://download.suse.com/patch/finder/?keywords=8944e139fcc8a84a52412d23cce7f98a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8b31cc6"
  );
  # https://download.suse.com/patch/finder/?keywords=a5e2892de750f2c5d2fba65db2f8b808
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c8f1473"
  );
  # https://download.suse.com/patch/finder/?keywords=afe31f60701fa39738b0574722eb95ef
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d3e3539"
  );
  # https://download.suse.com/patch/finder/?keywords=cfbfe04e5c8b61b50f91d849de2217e9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?958976ab"
  );
  # https://download.suse.com/patch/finder/?keywords=ef5762f62e2e26eab3ef31d6b58ad159
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5151205f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2010-5313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-6657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9585.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150652-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25324753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-kernel=10315 slessp1-kernel=10316
slessp1-kernel=10317

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-ec2-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"kernel-pae-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"kernel-default-man-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-default-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-source-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-syms-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"kernel-trace-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-ec2-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-xen-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-base-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"kernel-pae-devel-2.6.32.59-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.9.17")) flag++;


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
