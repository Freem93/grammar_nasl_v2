#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82638);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/08 13:41:02 $");

  script_cve_id("CVE-2014-8159", "CVE-2014-8867");

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
"  - It was found that the Linux kernel's Infiniband
    subsystem did not properly sanitize input parameters
    while registering memory regions from user space via the
    (u)verbs API. A local user with access to a
    /dev/infiniband/uverbsX device could use this flaw to
    crash the system or, potentially, escalate their
    privileges on the system. (CVE-2014-8159, Important)

  - An insufficient bound checking flaw was found in the Xen
    hypervisor's implementation of acceleration support for
    the 'REP MOVS' instructions. A privileged HVM guest user
    could potentially use this flaw to crash the host.
    (CVE-2014-8867, Important)

This update also fixes the following bugs :

  - Under memory pressure, cached data was previously
    flushed to the backing server using the PID of the
    thread responsible for flushing the data in the Server
    Message Block (SMB) headers instead of the PID of the
    thread which actually wrote the data. As a consequence,
    when a file was locked by the writing thread prior to
    writing, the server considered writes by the thread
    flushing the pagecache as being a separate process from
    writing to a locked file, and thus rejected the writes.
    In addition, the data to be written was discarded. This
    update ensures that the correct PID is sent to the
    server, and data corruption is avoided when data is
    being written from a client under memory pressure.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=602
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11de0e1e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-404.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-404.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
