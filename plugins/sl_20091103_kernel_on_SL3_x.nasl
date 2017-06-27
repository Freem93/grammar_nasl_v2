#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60688);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2008-5029", "CVE-2008-5300", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1895", "CVE-2009-2848", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3547");

  script_name(english:"Scientific Linux Security Update : kernel on SL3.x i386/x86_64");
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
"CVE-2008-5029 kernel: Unix sockets kernel panic

CVE-2008-5300 kernel: fix soft lockups/OOM issues with unix socket
garbage collector

CVE-2009-1337 kernel: exit_notify: kill the wrong capable(CAP_KILL)
check

CVE-2009-1385 kernel: e1000_clean_rx_irq() denial of service

CVE-2009-1895 kernel: personality: fix PER_CLEAR_ON_SETID

CVE-2009-2848 kernel: execve: must clear current->clear_child_tid

CVE-2009-3001, CVE-2009-3002 kernel: numerous getname() infoleaks
520300 - kernel: ipv4: make ip_append_data() handle NULL routing table
[rhel-3]

CVE-2009-3547 kernel: fs: pipe.c NULL pointer dereference

Security fixes :

  - when fput() was called to close a socket, the
    __scm_destroy() function in the Linux kernel could make
    indirect recursive calls to itself. This
    could,potentially, lead to a denial of service issue.
    (CVE-2008-5029, Important)

  - the sendmsg() function in the Linux kernel did not block
    during UNIX socket garbage collection. This could,
    potentially, lead to a local denial of service.
    (CVE-2008-5300, Important)

  - the exit_notify() function in the Linux kernel did not
    properly reset the exit signal if a process executed a
    set user ID (setuid) application before exiting. This
    could allow a local, unprivileged user to elevate their
    privileges. (CVE-2009-1337, Important)

  - a flaw was found in the Intel PRO/1000 network driver in
    the Linux kernel. Frames with sizes near the MTU of an
    interface may be split across multiple hardware receive
    descriptors. Receipt of such a frame could leak through
    a validation check, leading to a corruption of the
    length check. A remote attacker could use this flaw to
    send a specially crafted packet that would cause a
    denial of service or code execution. (CVE-2009-1385,
    Important)

  - the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not
    cleared when a setuid or setgid program was executed. A
    local, unprivileged user could use this flaw to bypass
    the mmap_min_addr protection mechanism and perform a
    NULL pointer dereference attack, or bypass the Address
    Space Layout Randomization (ASLR) security feature.
    (CVE-2009-1895, Important)

  - it was discovered that, when executing a new process,
    the clear_child_tid pointer in the Linux kernel is not
    cleared. If this pointer points to a writable portion of
    the memory of the new program, the kernel could corrupt
    four bytes of memory, possibly leading to a local denial
    of service or privilege escalation. (CVE-2009-2848,
    Important)

  - missing initialization flaws were found in getname()
    implementations in the IrDA sockets, AppleTalk DDP
    protocol, NET/ROM protocol, and ROSE protocol
    implementations in the Linux kernel. Certain data
    structures in these getname() implementations were not
    initialized properly before being copied to user-space.
    These flaws could lead to an information leak.
    (CVE-2009-3002, Important)

  - a NULL pointer dereference flaw was found in each of the
    following functions in the Linux kernel:
    pipe_read_open(), pipe_write_open(), and
    pipe_rdwr_open(). When the mutex lock is not held, the
    i_pipe pointer could be released by other processes
    before it is used to update the pipe's reader and writer
    counters. This could lead to a local denial of service
    or privilege escalation. (CVE-2009-3547, Important)

Bug fixes :

  - this update adds the mmap_min_addr tunable and
    restriction checks to help prevent unprivileged users
    from creating new memory mappings below the minimum
    address. This can help prevent the exploitation of NULL
    pointer dereference bugs. Note that mmap_min_addr is set
    to zero (disabled) by default for backwards
    compatibility. (BZ#512642)

  - a bridge reference count problem in IPv6 has been fixed.
    (BZ#457010)

  - enforce null-termination of user-supplied arguments to
    setsockopt(). (BZ#505514)

  - the gcc flag '-fno-delete-null-pointer-checks' was added
    to the kernel build options. This prevents gcc from
    optimizing out NULL pointer checks after the first use
    of a pointer. NULL pointer bugs are often exploited by
    attackers. Keeping these checks is a safety measure.
    (BZ#511185)

  - a check has been added to the IPv4 code to make sure
    that rt is not NULL, to help prevent future bugs in
    functions that call ip_append_data() from being
    exploitable. (BZ#520300)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=599
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e44095ea"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=457010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=505514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=511185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=520300"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
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
if (rpm_check(release:"SL3", reference:"kernel-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-doc-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-source-2.4.21-63.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-unsupported-2.4.21-63.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
