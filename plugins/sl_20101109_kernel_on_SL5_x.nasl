#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60886);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-3066", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3086", "CVE-2010-3477");

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

  - A NULL pointer dereference flaw was found in the
    io_submit_one() function in the Linux kernel
    asynchronous I/O implementation. A local, unprivileged
    user could use this flaw to cause a denial of service.
    (CVE-2010-3066, Moderate)

  - A flaw was found in the xfs_ioc_fsgetxattr() function in
    the Linux kernel XFS file system implementation. A data
    structure in xfs_ioc_fsgetxattr() was not initialized
    properly before being copied to user-space. A local,
    unprivileged user could use this flaw to cause an
    information leak. (CVE-2010-3078, Moderate)

  - The exception fixup code for the __futex_atomic_op1,
    __futex_atomic_op2, and futex_atomic_cmpxchg_inatomic()
    macros replaced the LOCK prefix with a NOP instruction.
    A local, unprivileged user could use this flaw to cause
    a denial of service. (CVE-2010-3086, Moderate)

  - A flaw was found in the tcf_act_police_dump() function
    in the Linux kernel network traffic policing
    implementation. A data structure in
    tcf_act_police_dump() was not initialized properly
    before being copied to user-space. A local, unprivileged
    user could use this flaw to cause an information leak.
    (CVE-2010-3477, Moderate)

  - A missing upper bound integer check was found in the
    sys_io_submit() function in the Linux kernel
    asynchronous I/O implementation. A local, unprivileged
    user could use this flaw to cause an information leak.
    (CVE-2010-3067, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1011&L=scientific-linux-errata&T=0&P=533
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d051f71d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-194.26.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-194.26.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
