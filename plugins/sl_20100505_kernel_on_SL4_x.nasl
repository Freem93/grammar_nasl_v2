#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60787);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2010-0729", "CVE-2010-1083", "CVE-2010-1085", "CVE-2010-1086", "CVE-2010-1188");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes :

  - Kernel update 2.6.9-89.EL introduced a flaw in the
    ptrace implementation on Itanium systems.
    ptrace_check_attach() was not called during certain
    ptrace() requests. Under certain circumstances, a local,
    unprivileged user could use this flaw to call ptrace()
    on a process they do not own, giving them control over
    that process. (CVE-2010-0729, Important)

  - a flaw was found in the kernel's Unidirectional
    Lightweight Encapsulation (ULE) implementation. A remote
    attacker could send a specially crafted ISO MPEG-2
    Transport Stream (TS) frame to a target system,
    resulting in a denial of service. (CVE-2010-1086,
    Important)

  - a use-after-free flaw was found in
    tcp_rcv_state_process() in the kernel's TCP/IP protocol
    suite implementation. If a system using IPv6 had the
    IPV6_RECVPKTINFO option set on a listening socket, a
    remote attacker could send an IPv6 packet to that
    system, causing a kernel panic. (CVE-2010-1188,
    Important)

  - a divide-by-zero flaw was found in azx_position_ok() in
    the Intel High Definition Audio driver, snd-hda-intel. A
    local, unprivileged user could trigger this flaw to
    cause a denial of service. (CVE-2010-1085, Moderate)

  - an information leak flaw was found in the kernel's USB
    implementation. Certain USB errors could result in an
    uninitialized kernel buffer being sent to user-space. An
    attacker with physical access to a target system could
    use this flaw to cause an information leak.
    (CVE-2010-1083, Low)

Bug fixes :

  - a regression prevented the Broadcom BCM5761 network
    device from working when in the first (top) PCI-E slot
    of Hewlett-Packard (HP) Z600 systems. Note: The card
    worked in the 2nd or 3rd PCI-E slot. (BZ#567205)

  - the Xen hypervisor supports 168 GB of RAM for 32-bit
    guests. The physical address range was set incorrectly,
    however, causing 32-bit, para-virtualized Scientific
    Linux 4.8 guests to crash when launched on AMD64 or
    Intel 64 hosts that have more than 64 GB of RAM.
    (BZ#574392)

  - Kernel update 2.6.9-89.EL introduced a regression,
    causing diskdump to fail on systems with certain
    adapters using the qla2xxx driver. (BZ#577234)

  - a race condition caused TX to stop in a guest using the
    virtio_net driver. (BZ#580089)

  - on some systems, using the 'arp_validate=3' bonding
    option caused both links to show as 'down' even though
    the arp_target was responding to ARP requests sent by
    the bonding driver. (BZ#580842)

  - in some circumstances, when a Scientific Linux client
    connected to a re-booted Windows-based NFS server,
    server-side filehandle-to-inode mapping changes caused a
    kernel panic. 'bad_inode_ops' handling was changed to
    prevent this. Note: filehandle-to-inode mapping changes
    may still cause errors, but not panics. (BZ#582908)

  - when installing a Scientific Linux 4 guest via PXE,
    hard-coded fixed-size scatterlists could conflict with
    host requests, causing the guest's kernel to panic. With
    this update, dynamically allocated scatterlists are
    used, resolving this issue. (BZ#582911)

Enhancements :

  - kernel support for connlimit. Note: iptables errata
    update RHBA-2010:0395 is also required for connlimit to
    work correctly. (BZ#563223)

  - support for the Intel architectural performance
    monitoring subsystem (arch_perfmon). On supported CPUs,
    arch_perfmon offers means to mark performance events and
    options for configuring and counting these events.
    (BZ#582913)

  - kernel support for OProfile sampling of Intel
    microarchitecture (Nehalem) CPUs. This update alone does
    not address OProfile support for such CPUs. A future
    oprofile package update will allow OProfile to work on
    Intel Nehalem CPUs. (BZ#582241)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1005&L=scientific-linux-errata&T=0&P=588
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8ee1882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=563223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=567205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=574392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=580842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=582241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=582908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=582911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=582913"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.25.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.25.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
