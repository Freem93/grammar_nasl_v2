#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(74489);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/12 10:50:12 $");

  script_cve_id("CVE-2013-7339", "CVE-2014-1737", "CVE-2014-1738");

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
"  - A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain error
    code paths while processing FDRAWCMD IOCTL commands. A
    local user with write access to /dev/fdX could use this
    flaw to free (using the kfree() function) arbitrary
    kernel memory. (CVE-2014-1737, Important)

  - It was found that the Linux kernel's floppy driver
    leaked internal kernel memory addresses to user space
    during the processing of the FDRAWCMD IOCTL command. A
    local user with write access to /dev/fdX could use this
    flaw to obtain information about the kernel heap
    arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two
flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate
their privileges on the system.

  - A NULL pointer dereference flaw was found in the
    rds_ib_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system. (CVE-2013-7339, Moderate)

This update also fixes the following bugs :

  - A bug in the futex system call could result in an
    overflow when passing a very large positive timeout. As
    a consequence, the FUTEX_WAIT operation did not work as
    intended and the system call was timing out immediately.
    A backported patch fixes this bug by limiting very large
    positive timeouts to the maximal supported value.

  - A new Linux Security Module (LSM) functionality related
    to the setrlimit hooks should produce a warning message
    when used by a third party module that could not cope
    with it. However, due to a programming error, the kernel
    could print this warning message when a process was
    setting rlimits for a different process, or if rlimits
    were modified by another than the main thread even
    though there was no incompatible third party module.
    This update fixes the relevant code and ensures that the
    kernel handles this warning message correctly.

  - Previously, the kernel was unable to detect KVM on
    system boot if the Hyper-V emulation was enabled. A
    patch has been applied to ensure that both KVM and
    Hyper-V hypervisors are now correctly detected during
    system boot.

  - A function in the RPC code responsible for verifying
    whether cached credentials match the current process did
    not perform the check correctly. The code checked only
    whether the groups in the current process credentials
    appear in the same order as in the cached credentials
    but did not ensure that no other groups are present in
    the cached credentials. As a consequence, when accessing
    files in NFS mounts, a process with the same UID and GID
    as the original process but with a non-matching group
    list could have been granted an unauthorized access to a
    file, or under certain circumstances, the process could
    have been wrongly prevented from accessing the file. The
    incorrect test condition has been fixed and the problem
    can no longer occur.

  - When being under heavy load, some Fibre Channel storage
    devices, such as Hitachi and HP Open-V series, can send
    a logout (LOGO) message to the host system. However, due
    to a bug in the lpfc driver, this could result in a loss
    of active paths to the storage and the paths could not
    be recovered without manual intervention. This update
    corrects the lpfc driver to ensure automatic recovery of
    the lost paths to the storage in this scenario.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=1720
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d53228c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.9.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
