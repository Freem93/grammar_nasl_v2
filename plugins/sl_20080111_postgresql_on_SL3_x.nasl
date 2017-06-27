#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60343);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");

  script_name(english:"Scientific Linux Security Update : postgresql on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Will Drewry discovered multiple flaws in PostgreSQL's regular
expression engine. An authenticated attacker could use these flaws to
cause a denial of service by causing the PostgreSQL server to crash,
enter an infinite loop, or use extensive CPU and memory resources
while processing queries containing specially crafted regular
expressions. Applications that accept regular expressions from
untrusted sources may expose this problem to unauthorized attackers.
(CVE-2007-4769, CVE-2007-4772, CVE-2007-6067)

A privilege escalation flaw was discovered in PostgreSQL. An
authenticated attacker could create an index function that would be
executed with administrator privileges during database maintenance
tasks, such as database vacuuming. (CVE-2007-6600)

A privilege escalation flaw was discovered in PostgreSQL's Database
Link library (dblink). An authenticated attacker could use dblink to
possibly escalate privileges on systems with 'trust' or 'ident'
authentication configured. Please note that dblink functionality is
not enabled by default, and can only by enabled by a database
administrator on systems with the postgresql-contrib package
installed. (CVE-2007-3278, CVE-2007-6601)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=717
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e170ebc6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/11");
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
if (rpm_check(release:"SL3", reference:"rh-postgresql-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-contrib-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-devel-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-docs-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-jdbc-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-libs-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-pl-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-python-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-server-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-tcl-7.3.21-1")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-test-7.3.21-1")) flag++;

if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-contrib-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-contrib-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-devel-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-devel-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-docs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-docs-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-jdbc-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-libs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-libs-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-pl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-pl-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-python-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-python-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-server-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-server-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-tcl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-tcl-7.4.19-1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"postgresql-test-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"postgresql-test-7.4.19-1.el4.1")) flag++;

if (rpm_check(release:"SL5", reference:"postgresql-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.11-1.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
