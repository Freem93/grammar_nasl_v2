#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82469);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");

  script_name(english:"Scientific Linux Security Update : postgresql on SL6.x, SL7.x i386/x86_64");
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
"An information leak flaw was found in the way the PostgreSQL database
server handled certain error messages. An authenticated database user
could possibly obtain the results of a query they did not have
privileges to execute by observing the constraint violation error
messages produced when the query was executed. (CVE-2014-8161)

A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a
specially crafted timestamp formatting template to cause PostgreSQL to
crash or, under certain conditions, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0241)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto
module. An authenticated database user could use this flaw to cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in the way PostgreSQL handled certain errors that
were generated during protocol synchronization. An authenticated
database user could use this flaw to inject queries into an existing
connection. (CVE-2015-0244)

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=4261
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e50c656"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
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
if (rpm_check(release:"SL6", reference:"postgresql-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.20-2.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-debuginfo-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-devel-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-docs-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-libs-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-server-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-test-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.10-2.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
