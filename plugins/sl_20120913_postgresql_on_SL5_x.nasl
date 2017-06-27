#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62109);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-3488");

  script_name(english:"Scientific Linux Security Update : postgresql on SL5.x i386/x86_64");
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
"It was found that the optional PostgreSQL xml2 contrib module allowed
local files and remote URLs to be read and written to with the
privileges of the database server when parsing Extensible Stylesheet
Language Transformations (XSLT). An unprivileged database user could
use this flaw to read and write to local files (such as the database's
configuration files) and remote URLs they would otherwise not have
access to by issuing a specially crafted SQL query. (CVE-2012-3488)

We would like to thank the PostgreSQL project for reporting this
issue. Upstream acknowledges Peter Eisentraut as the original
reporter.

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=1883
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cf76c47"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/15");
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
if (rpm_check(release:"SL5", reference:"postgresql-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.23-6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.23-6.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
