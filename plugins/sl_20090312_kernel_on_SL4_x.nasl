#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60543);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-5700", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322");

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
"This update addresses the following security issues :

  - a buffer overflow was found in the Linux kernel Partial
    Reliable Stream Control Transmission Protocol (PR-SCTP)
    implementation. This could, potentially, lead to a
    denial of service if a Forward-TSN chunk is received
    with a large stream ID. (CVE-2009-0065, Important)

  - a memory leak was found in keyctl handling. A local,
    unprivileged user could use this flaw to deplete kernel
    memory, eventually leading to a denial of service.
    (CVE-2009-0031, Important)

  - a deficiency was found in the Remote BIOS Update (RBU)
    driver for Dell systems. This could allow a local,
    unprivileged user to cause a denial of service by
    reading zero bytes from the image_type or packet_size
    file in '/sys/devices/platform/dell_rbu/'.
    (CVE-2009-0322, Important)

  - a deficiency was found in the libATA implementation.
    This could, potentially, lead to a denial of service.
    Note: by default, '/dev/sg*' devices are accessible only
    to the root user. (CVE-2008-5700, Low)

This update also fixes the following bugs :

  - when the hypervisor changed a page table entry (pte)
    mapping from read-only to writable via a make_writable
    hypercall, accessing the changed page immediately
    following the change caused a spurious page fault. When
    trying to install a para-virtualized Scientific Linux 4
    guest on a Scientific Linux 5.3 dom0 host, this fault
    crashed the installer with a kernel backtrace. With this
    update, the 'spurious' page fault is handled properly.
    (BZ#483748)

  - net_rx_action could detect its cpu poll_list as
    non-empty, but have that same list reduced to empty by
    the poll_napi path. This resulted in garbage data being
    returned when net_rx_action calls list_entry, which
    subsequently resulted in several possible crash
    conditions. The race condition in the network code which
    caused this has been fixed. (BZ#475970, BZ#479681 &amp;
    BZ#480741)

  - a misplaced memory barrier at unlock_buffer() could lead
    to a concurrent h_refcounter update which produced a
    reference counter leak and, later, a double free in
    ext3_xattr_release_block(). Consequent to the double
    free, ext3 reported an error

    ext3_free_blocks_sb: bit already cleared for block
    [block number]

    and mounted itself as read-only. With this update, the
    memory barrier is now placed before the buffer head lock
    bit, forcing the write order and preventing the double
    free. (BZ#476533)

  - when the iptables module was unloaded, it was assumed
    the correct entry for removal had been found if
    'wrapper->ops->pf' matched the value passed in by
    'reg->pf'. If several ops ranges were registered against
    the same protocol family, however, (which was likely if
    you had both ip_conntrack and ip_contrack_* loaded) this
    assumption could lead to NULL list pointers and cause a
    kernel panic. With this update, 'wrapper->ops' is
    matched to pointer values 'reg', which ensures the
    correct entry is removed and results in no NULL list
    pointers. (BZ#477147)

  - when the pidmap page (used for tracking process ids,
    pids) incremented to an even page (ie the second,
    fourth, sixth, etc. pidmap page), the alloc_pidmap()
    routine skipped the page. This resulted in 'holes' in
    the allocated pids. For example, after pid 32767, you
    would expect 32768 to be allocated. If the page skipping
    behavior presented, however, the pid allocated after
    32767 was 65536. With this update, alloc_pidmap() no
    longer skips alternate pidmap pages and allocated pid
    holes no longer occur. This fix also corrects an error
    which allowed pid_max to be set higher than the pid_max
    limit has been corrected. (BZ#479182)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0903&L=scientific-linux-errata&T=0&P=1320
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24851b3d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=475970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=477147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=479182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=479681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=480741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483748"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/12");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-78.0.17.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-78.0.17.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
