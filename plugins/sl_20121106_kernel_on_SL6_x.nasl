#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62858);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/08 14:23:04 $");

  script_cve_id("CVE-2012-1568", "CVE-2012-2133", "CVE-2012-3400", "CVE-2012-3511");

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
"* A use-after-free flaw was found in the Linux kernel's memory
management subsystem in the way quota handling for huge pages was
performed. A local, unprivileged user could use this flaw to cause a
denial of service or, potentially, escalate their privileges.
(CVE-2012-2133, Moderate)

* A use-after-free flaw was found in the madvise() system call
implementation in the Linux kernel. A local, unprivileged user could
use this flaw to cause a denial of service or, potentially, escalate
their privileges. (CVE-2012-3511, Moderate)

* It was found that when running a 32-bit binary that uses a large
number of shared libraries, one of the libraries would always be
loaded at a predictable address in memory. An attacker could use this
flaw to bypass the Address Space Layout Randomization (ASLR) security
feature. (CVE-2012-1568, Low)

* Buffer overflow flaws were found in the udf_load_logicalvol()
function in the Universal Disk Format (UDF) file system implementation
in the Linux kernel. An attacker with physical access to a system
could use these flaws to cause a denial of service or escalate their
privileges. (CVE-2012-3400, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1211&L=scientific-linux-errata&T=0&P=308
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7edf6da8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/08");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-279.14.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-279.14.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
