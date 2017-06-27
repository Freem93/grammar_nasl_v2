#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61294);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");

  script_name(english:"Scientific Linux Security Update : rpm on SL5.x, SL6.x i386/x86_64");
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
"The RPM Package Manager (RPM) is a command-line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library (such
as the rpm command line tool, or the yum and up2date package managers)
to crash or, potentially, execute arbitrary code. (CVE-2012-0060,
CVE-2012-0061, CVE-2012-0815)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dd021ae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"popt-1.10.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-debuginfo-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-devel-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-libs-4.4.2.3-28.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"rpm-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-apidocs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-cron-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-debuginfo-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-devel-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-libs-4.8.0-19.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
