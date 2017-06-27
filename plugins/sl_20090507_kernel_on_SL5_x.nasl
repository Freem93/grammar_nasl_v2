#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60581);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2008-4307", "CVE-2009-0787", "CVE-2009-0834", "CVE-2009-1336", "CVE-2009-1337");

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
"This update fixes the following security issues :

  - a logic error was found in the do_setlk() function of
    the Linux kernel Network File System (NFS)
    implementation. If a signal interrupted a lock request,
    the local POSIX lock was incorrectly created. This could
    cause a denial of service on the NFS server if a file
    descriptor was closed before its corresponding lock
    request returned. (CVE-2008-4307, Important)

  - a deficiency was found in the Linux kernel system call
    auditing implementation on 64-bit systems. This could
    allow a local, unprivileged user to circumvent a system
    call audit configuration, if that configuration filtered
    based on the 'syscall' number or arguments.
    (CVE-2009-0834, Important)

  - the exit_notify() function in the Linux kernel did not
    properly reset the exit signal if a process executed a
    set user ID (setuid) application before exiting. This
    could allow a local, unprivileged user to elevate their
    privileges. (CVE-2009-1337, Important)

  - a flaw was found in the
    ecryptfs_write_metadata_to_contents() function of the
    Linux kernel eCryptfs implementation. On systems with a
    4096 byte page-size, this flaw may have caused 4096
    bytes of uninitialized kernel memory to be written into
    the eCryptfs file headers, leading to an information
    leak. Note: Encrypted files created on systems running
    the vulnerable version of eCryptfs may contain leaked
    data in the eCryptfs file headers. This update does not
    remove any leaked data. Refer to the Knowledgebase
    article in the References section for further
    information. (CVE-2009-0787, Moderate)

  - the Linux kernel implementation of the Network File
    System (NFS) did not properly initialize the file name
    limit in the nfs_server data structure. This flaw could
    possibly lead to a denial of service on a client
    mounting an NFS share. (CVE-2009-1336, Moderate)

This update also fixes the following bugs :

  - the enic driver (Cisco 10G Ethernet) did not operate
    under virtualization. (BZ#472474)

  - network interfaces using the IBM eHEA Ethernet device
    driver could not be successfully configured under
    low-memory conditions. (BZ#487035)

  - bonding with the 'arp_validate=3' option may have
    prevented fail overs. (BZ#488064)

  - when running under virtualization, the acpi-cpufreq
    module wrote 'Domain attempted WRMSR' errors to the
    dmesg log. (BZ#488928)

  - NFS clients may have experienced deadlocks during
    unmount. (BZ#488929)

  - the ixgbe driver double counted the number of received
    bytes and packets. (BZ#489459)

  - the Wacom Intuos3 Lens Cursor device did not work
    correctly with the Wacom Intuos3 12x12 tablet.
    (BZ#489460)

  - on the Itanium&reg; architecture, nanosleep() caused
    commands which used it, such as sleep and usleep, to
    sleep for one second more than expected. (BZ#490434)

  - a panic and corruption of slab cache data structures
    occurred on 64-bit PowerPC systems when clvmd was
    running. (BZ#491677)

  - the NONSTOP_TSC feature did not perform correctly on the
    Intel&reg; microarchitecture (Nehalem) when running in
    32-bit mode. (BZ#493356)

  - keyboards may not have functioned on IBM eServer System
    p machines after a certain point during installation or
    afterward. (BZ#494293)

  - using Device Mapper Multipathing with the qla2xxx driver
    resulted in frequent path failures. (BZ#495635)

  - if the hypervisor was booted with the dom0_max_vcpus
    parameter set to less than the actual number of CPUs in
    the system, and the cpuspeed service was started, the
    hypervisor could crash. (BZ#495931)

  - using Openswan to provide an IPsec virtual private
    network eventually resulted in a CPU soft lockup and a
    system crash. (BZ#496044)

  - it was possible for posix_locks_deadlock() to enter an
    infinite loop (under the BKL), causing a system hang.
    (BZ#496842)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0905&L=scientific-linux-errata&T=0&P=541
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c8842a0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=472474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=489459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=489460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=490434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=491677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=493356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=494293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=495635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=495931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496842"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(20, 189, 264, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/07");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-128.1.10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-128.1.10.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
