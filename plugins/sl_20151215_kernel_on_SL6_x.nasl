#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87403);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/28 21:03:38 $");

  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"  - A flaw was found in the way the Linux kernel's file
    system implementation handled rename operations in which
    the source was inside and the destination was outside of
    a bind mount. A privileged user inside a container could
    use this flaw to escape the bind mount and, potentially,
    escalate their privileges on the system. (CVE-2015-2925,
    Important)

  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as #AC
    (alignment check exception) and #DB (debug exception) is
    handled. A privileged user inside a guest could use
    these flaws to create denial of service conditions on
    the host kernel. (CVE-2015-5307, CVE-2015-8104,
    Important)

  - A race condition flaw was found in the way the Linux
    kernel's IPC subsystem initialized certain fields in an
    IPC object structure that were later used for permission
    checking before inserting the object into a globally
    visible list. A local, unprivileged user could
    potentially use this flaw to elevate their privileges on
    the system. (CVE-2015-7613, Important)

  - It was found that the Linux kernel's keys subsystem did
    not correctly garbage collect uninstantiated keyrings. A
    local attacker could use this flaw to crash the system
    or, potentially, escalate their privileges on the
    system. (CVE-2015-7872, Important)

This update also fixes the following bugs :

  - Previously, Human Interface Device (HID) ran a report on
    an unaligned buffer, which could cause a page fault
    interrupt and an oops when the end of the report was
    read. This update fixes this bug by padding the end of
    the report with extra bytes, so the reading of the
    report never crosses a page boundary. As a result, a
    page fault and subsequent oops no longer occur.

  - The NFS client was previously failing to detect a
    directory loop for some NFS server directory structures.
    This failure could cause NFS inodes to remain referenced
    after attempting to unmount the file system, leading to
    a kernel crash. Loop checks have been added to VFS,
    which effectively prevents this problem from occurring.

  - Due to a race whereby the nfs_wb_pages_cancel() and
    nfs_commit_release_pages() calls both removed a request
    from the nfs_inode struct type, the kernel panicked with
    negative nfs_inode.npages count. The provided upstream
    patch performs the required serialization by holding the
    inode i_lock over the check of PagePrivate and locking
    the request, thus preventing the race and kernel panic
    from occurring.

  - Due to incorrect URB_ISO_ASAP semantics, playing an
    audio file using a USB sound card could previously fail
    for some hardware configurations. This update fixes the
    bug, and playing audio from a USB sound card now works
    as expected.

  - Inside hugetlb, region data structures were protected by
    a combination of a memory map semaphore and a single
    hugetlb instance mutex. However, a page-fault
    scalability improvement backported to the kernel on
    previous releases removed the single hugetlb instance
    mutex and introduced a new mutex table, making the
    locking combination insufficient, leading to possible
    race windows that could cause corruption and undefined
    behavior. This update fixes the problem by introducing a
    required spinlock to the region tracking functions for
    proper serialization. The problem only affects software
    using huge pages through hugetlb interface.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=1991
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3efa1471"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.12.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.12.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
