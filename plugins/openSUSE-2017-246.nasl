#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-246.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97138);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/14 17:23:21 $");

  script_cve_id("CVE-2016-10088", "CVE-2016-10147", "CVE-2016-7117", "CVE-2016-7917", "CVE-2016-8645", "CVE-2016-9576", "CVE-2016-9793", "CVE-2016-9806", "CVE-2017-5551");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-246)");
  script_summary(english:"Check for the openSUSE-2017-246 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 kernel to 4.1.38 to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077).

  - CVE-2017-5551: tmpfs: Fixed a bug that could have
    allowed users to set setgid bits on files they don't
    down (bsc#1021258).

  - CVE-2016-10147: crypto/mcryptd.c in the Linux kernel
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) by using an AF_ALG
    socket with an incompatible algorithm, as demonstrated
    by mcryptd(md5) (bnc#1020381).

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2016-7917: The nfnetlink_rcv_batch function in
    net/netfilter/nfnetlink.c in the Linux kernel did not
    check whether a batch message's length field is large
    enough, which allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (infinite loop or out-of-bounds read) by
    leveraging the CAP_NET_ADMIN capability (bnc#1010444).

  - CVE-2016-8645: The TCP stack in the Linux kernel
    mishandled skb truncation, which allowed local users to
    cause a denial of service (system crash) via a crafted
    application that made sendto system calls, related to
    net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c
    (bnc#1009969).

  - CVE-2016-9806: Race condition in the netlink_dump
    function in net/netlink/af_netlink.c in the Linux kernel
    allowed local users to cause a denial of service (double
    free) or possibly have unspecified other impact via a
    crafted application that made sendmsg system calls,
    leading to a free operation associated with a new dump
    that started earlier than anticipated (bnc#1013540
    1017589).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option (bnc#1013531
    1013542).

The following non-security bugs were fixed :

  - PCI: generic: Fix pci_remap_iospace() failure path
    (bsc#1019658).

  - bcache: partition support: add 16 minors per bcacheN
    device (bsc#1019784).

  - bnx2x: Correct ringparam estimate when DOWN
    (bsc#1020214).

  - clk: xgene: Do not call __pa on ioremaped address
    (bsc#1019660).

  - kABI workaround for 4.1.37 mount changes
    (stable-4.1.37).

  - kABI: reintroduce sk_filter (bsc#1009969).

  - kabi/severities: Ignore inode_change_ok change It's
    renamed in 4.1.37 to setattr_prepare()

  - mpi: Fix NULL ptr dereference in mpi_powm() [ver #3]
    (bsc#1011820).

  - net: introduce __sock_queue_rcv_skb() function
    (bsc#1009969).

  - netback: correct array index (bsc#983348).

  - netfront: do not truncate grant references.

  - netfront: use correct linear area after linearizing an
    skb (bsc#1007886).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rose: limit sk_filter trim to payload (bsc#1009969).

  - scsi: bfa: Increase requested firmware version to
    3.2.5.1 (bsc#1013273).

  - xenbus: correctly signal errors from
    xenstored_local_init() (luckily none so far).

  - xenbus: do not invoke ->is_ready() for most device
    states (bsc#987333)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987576"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.38-47.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.38-47.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.38-47.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.38-47.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.38-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.38-47.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
