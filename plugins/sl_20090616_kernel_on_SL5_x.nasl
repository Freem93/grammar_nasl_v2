#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60599);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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

  - several flaws were found in the way the Linux kernel
    CIFS implementation handles Unicode strings. CIFS
    clients convert Unicode strings sent by a server to
    their local character sets, and then write those strings
    into memory. If a malicious server sent a long enough
    string, it could write past the end of the target memory
    region and corrupt other memory areas, possibly leading
    to a denial of service or privilege escalation on the
    client mounting the CIFS share. (CVE-2009-1439,
    CVE-2009-1633, Important)

  - the Linux kernel Network File System daemon (nfsd)
    implementation did not drop the CAP_MKNOD capability
    when handling requests from local, unprivileged users.
    This flaw could possibly lead to an information leak or
    privilege escalation. (CVE-2009-1072, Moderate)

  - Frank Filz reported the NFSv4 client was missing a file
    permission check for the execute bit in some situations.
    This could allow local, unprivileged users to run
    non-executable files on NFSv4 mounted file systems.
    (CVE-2009-1630, Moderate)

  - a missing check was found in the hypervisor_callback()
    function in the Linux kernel provided by the kernel-xen
    package. This could cause a denial of service of a
    32-bit guest if an application running in that guest
    accesses a certain memory location in the kernel.
    (CVE-2009-1758, Moderate)

  - a flaw was found in the AGPGART driver. The
    agp_generic_alloc_page() and agp_generic_alloc_pages()
    functions did not zero out the memory pages they
    allocate, which may later be available to user-space
    processes. This flaw could possibly lead to an
    information leak. (CVE-2009-1192, Low)

Bug fixes :

  - a race in the NFS client between destroying cached
    access rights and unmounting an NFS file system could
    have caused a system crash. 'Busy inodes' messages may
    have been logged. (BZ#498653)

  - nanosleep() could sleep several milliseconds less than
    the specified time on Intel Itanium&reg;-based systems.
    (BZ#500349)

  - LEDs for disk drives in AHCI mode may have displayed a
    fault state when there were no faults. (BZ#500120)

  - ptrace_do_wait() reported tasks were stopped each time
    the process doing the trace called wait(), instead of
    reporting it once. (BZ#486945)

  - epoll_wait() may have caused a system lockup and
    problems for applications. (BZ#497322)

  - missing capabilities could possibly allow users with an
    fsuid other than 0 to perform actions on some file
    system types that would otherwise be prevented.
    (BZ#497271)

  - on NFS mounted file systems, heavy write loads may have
    blocked nfs_getattr() for long periods, causing commands
    that use stat(2), such as ls, to hang. (BZ#486926)

  - in rare circumstances, if an application performed
    multiple O_DIRECT reads per virtual memory page and also
    performed fork(2), the buffer storing the result of the
    I/O may have ended up with invalid data. (BZ#486921)

  - when using GFS2, gfs2_quotad may have entered an
    uninterpretable sleep state. (BZ#501742)

  - with this update, get_random_int() is more random and no
    longer uses a common seed value, reducing the
    possibility of predicting the values returned.
    (BZ#499783)

  - the '-fwrapv' flag was added to the gcc build options to
    prevent gcc from optimizing away wrapping. (BZ#501751)

  - a kernel panic when enabling and disabling iSCSI paths.
    (BZ#502916)

  - using the Broadcom NetXtreme BCM5704 network device with
    the tg3 driver caused high system load and very bad
    performance. (BZ#502837)

  - '/proc/[pid]/maps' and '/proc/[pid]/smaps' can only be
    read by processes able to use the ptrace() call on a
    given process; however, certain information from
    '/proc/[pid]/stat' and '/proc/[pid]/wchan' could be used
    to reconstruct memory maps. (BZ#499546)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=1325
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?092c5c8d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=486921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=486926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=486945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=498653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=499546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=499783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=501751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=502837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=502916"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/16");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-128.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-128.1.14.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
