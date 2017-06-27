#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(79759);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/06 16:28:19 $");

  script_cve_id("CVE-2014-0181");

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
"  - It was found that the permission checks performed by the
    Linux kernel when a netlink message was received were
    not sufficient. A local, unprivileged user could
    potentially bypass these restrictions by passing a
    netlink socket as stdout or stderr to a more privileged
    process and altering the output of this process.
    (CVE-2014-0181, Moderate)

This update also fixes the following bugs :

  - Previously, the kernel did not successfully deliver
    multicast packets when the multicast querier was
    disabled. Consequently, the corosync utility terminated
    unexpectedly and the affected storage node did not join
    its intended cluster. With this update, multicast
    packets are delivered properly when the multicast
    querier is disabled, and corosync handles the node as
    expected.

  - Previously, the kernel wrote the metadata contained in
    all system information blocks on a single page of the
    /proc/sysinfo file. However, when the machine
    configuration was very extensive and the data did not
    fit on a single page, the system overwrote random memory
    regions, which in turn caused data corruption when
    reading the /proc/sysconf file. With this update,
    /proc/sysinfo automatically allocates a larger buffer if
    the data output does not fit the current buffer, which
    prevents the data corruption.

  - Prior to this update, the it_real_fn() function did not,
    in certain cases, successfully acquire the SIGLOCK
    signal when the do_setitimer() function used the
    ITIMER_REAL timer. As a consequence, the current process
    entered an endless loop and became unresponsive. This
    update fixes the bug and it_real_fn() no longer causes
    the kernel to become unresponsive.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=1102
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3f30a35"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/06");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-400.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-400.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
