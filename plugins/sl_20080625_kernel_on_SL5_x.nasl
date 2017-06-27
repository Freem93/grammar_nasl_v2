#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60430);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-0598", "CVE-2008-2358", "CVE-2008-2729");

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
"These updated packages fix the following security issues :

  - A security flaw was found in the Linux kernel memory
    copy routines, when running on certain AMD64 systems. If
    an unsuccessful attempt to copy kernel memory from
    source to destination memory locations occurred, the
    copy routines did not zero the content at the
    destination memory location. This could allow a local
    unprivileged user to view potentially sensitive data.
    (CVE-2008-2729, Important)

  - Tavis Ormandy discovered a deficiency in the Linux
    kernel 32-bit and 64-bit emulation. This could allow a
    local unprivileged user to prepare and run a specially
    crafted binary, which would use this deficiency to leak
    uninitialized and potentially sensitive data.
    (CVE-2008-0598, Important)

  - Brandon Edwards discovered a missing length validation
    check in the Linux kernel DCCP module reconciliation
    feature. This could allow a local unprivileged user to
    cause a heap overflow, gaining privileges for arbitrary
    code execution. (CVE-2008-2358, Moderate)

As well, these updated packages fix the following bug :

  - Due to a regression, 'gettimeofday' may have gone
    backwards on certain x86 hardware. This issue was quite
    dangerous for time-sensitive systems, such as those used
    for transaction systems and databases, and may have
    caused applications to produce incorrect results, or
    even crash."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0806&L=scientific-linux-errata&T=0&P=2390
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62d6c871"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-92.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-92.1.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
