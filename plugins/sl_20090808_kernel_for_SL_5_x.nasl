#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60634);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2007-5966", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");

  script_name(english:"Scientific Linux Security Update : kernel for SL 5.x on i386/x86_64");
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
"CVE-2007-5966 kernel: non-root can trigger cpu_idle soft lockup
CVE-2009-1385 kernel: e1000_clean_rx_irq() denial of service
CVE-2009-1388 kernel: do_coredump() vs ptrace_start() deadlock
CVE-2009-1389 kernel: r8169: fix crash when large packets are received
CVE-2009-1895 kernel: personality: fix PER_CLEAR_ON_SETID
CVE-2009-2406 kernel: ecryptfs stack overflow in parse_tag_11_packet()
CVE-2009-2407 kernel: ecryptfs heap overflow in parse_tag_3_packet()

Security fixes :

  - the possibility of a timeout value overflow was found in
    the Linux kernel high-resolution timers functionality,
    hrtimers. This could allow a local, unprivileged user to
    execute arbitrary code, or cause a denial of service
    (kernel panic). (CVE-2007-5966, Important)

  - a flaw was found in the Intel PRO/1000 network driver in
    the Linux kernel. Frames with sizes near the MTU of an
    interface may be split across multiple hardware receive
    descriptors. Receipt of such a frame could leak through
    a validation check, leading to a corruption of the
    length check. A remote attacker could use this flaw to
    send a specially crafted packet that would cause a
    denial of service or code execution. (CVE-2009-1385,
    Important)

  - Michael Tokarev reported a flaw in the Realtek r8169
    Ethernet driver in the Linux kernel. This driver allowed
    interfaces using this driver to receive frames larger
    than could be handled, which could lead to a remote
    denial of service or code execution. (CVE-2009-1389,
    Important)

  - the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not
    cleared when a setuid or setgid program was executed. A
    local, unprivileged user could use this flaw to bypass
    the mmap_min_addr protection mechanism and perform a
    NULL pointer dereference attack, or bypass the Address
    Space Layout Randomization (ASLR) security feature.
    (CVE-2009-1895, Important)

  - Ramon de Carvalho Valle reported two flaws in the Linux
    kernel eCryptfs implementation. A local attacker with
    permissions to perform an eCryptfs mount could modify
    the metadata of the files in that eCrypfts mount to
    cause a buffer overflow, leading to a denial of service
    or privilege escalation. (CVE-2009-2406, CVE-2009-2407,
    Important)

  - Konstantin Khlebnikov discovered a race condition in the
    ptrace implementation in the Linux kernel. This race
    condition can occur when the process tracing and the
    process being traced participate in a core dump. A
    local, unprivileged user could use this flaw to trigger
    a deadlock, resulting in a partial denial of service.
    (CVE-2009-1388, Moderate)

Bug fixes :

  - possible host (dom0) crash when installing a Xen
    para-virtualized guest while another para-virtualized
    guest was rebooting. (BZ#497812)

  - no audit record for a directory removal if the directory
    and its subtree were recursively watched by an audit
    rule. (BZ#507561)

  - running 'echo 1 > /proc/sys/vm/drop_caches' on systems
    under high memory load could cause a kernel panic.
    (BZ#503692)

  - on 32-bit systems, core dumps for some multithreaded
    applications did not include all thread information.
    (BZ#505322)

  - a stack buffer used by get_event_name() was not large
    enough for the nul terminator sprintf() writes. This
    could lead to an invalid pointer or kernel panic.
    (BZ#506906)

  - when using the aic94xx driver, a system with SATA drives
    may not boot due to a bug in libsas. (BZ#506029)

  - incorrect stylus button handling when moving it away
    then returning it to the tablet for Wacom Cintiq 21UX
    and Intuos tablets. (BZ#508275)

  - CPU 'soft lockup' messages and possibly a system hang on
    systems with certain Broadcom network devices and
    running the Linux kernel from the kernel-xen package.
    (BZ#503689)

  - on 64-bit PowerPC, getitimer() failed for programs using
    the ITIMER_REAL timer and that were also compiled for
    64-bit systems (this caused such programs to abort).
    (BZ#510018)

  - write operations could be blocked even when using
    O_NONBLOCK. (BZ#510239)

  - the 'pci=nomsi' option was required for installing and
    booting Red Hat Enterprise Linux 5.2 on systems with VIA
    VT3364 chipsets. (BZ#507529)

  - shutting down, destroying, or migrating Xen guests with
    large amounts of memory could cause other guests to be
    temporarily unresponsive. (BZ#512311)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=77
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2340aeb2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=505322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=506029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=506906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=507529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=507561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=508275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=510018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=510239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512311"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 119, 189, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-128.4.1.el5-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-aufs-2.6.18-128.4.1.el5PAE-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-128.4.1.el5xen-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-fuse-2.6.18-128.4.1.el5-2.6.3-1.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-fuse-2.6.18-128.4.1.el5PAE-2.6.3-1.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-fuse-2.6.18-128.4.1.el5xen-2.6.3-1.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-128.4.1.el5-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ipw3945-2.6.18-128.4.1.el5PAE-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-128.4.1.el5xen-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-128.4.1.el5-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-2.6.18-128.4.1.el5PAE-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-128.4.1.el5xen-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-128.4.1.el5-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.18-128.4.1.el5PAE-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-128.4.1.el5xen-0.9.4-15.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-128.4.1.el5-1.53-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ndiswrapper-2.6.18-128.4.1.el5PAE-1.53-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-128.4.1.el5xen-1.53-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.4.1.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-128.4.1.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.4.1.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-xfs-2.6.18-128.4.1.el5-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-128.4.1.el5PAE-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-xfs-2.6.18-128.4.1.el5xen-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-128.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-128.4.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
