#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60795);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2009-4136", "CVE-2010-0442", "CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170");

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
"PostgreSQL is an advanced object-relational database management system
(DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions
in the Perl and Tcl languages, and are installed in trusted mode by
default. In trusted mode, certain operations, such as operating system
level access, are restricted.

A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Perl. If the PL/Perl procedural language was
registered on a particular database, an authenticated database user
running a specially crafted PL/Perl script could use this flaw to
bypass intended PL/Perl trusted mode restrictions, allowing them to
run arbitrary Perl scripts with the privileges of the database server.
(CVE-2010-1169)

A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Tcl. If the PL/Tcl procedural language was
registered on a particular database, an authenticated database user
running a specially crafted PL/Tcl script could use this flaw to
bypass intended PL/Tcl trusted mode restrictions, allowing them to run
arbitrary Tcl scripts with the privileges of the database server.
(CVE-2010-1170)

A buffer overflow flaw was found in the way PostgreSQL retrieved a
substring from the bit string for BIT() and BIT VARYING() SQL data
types. An authenticated database user running a specially crafted SQL
query could use this flaw to cause a temporary denial of service
(postgres daemon crash) or, potentially, execute arbitrary code with
the privileges of the database server. (CVE-2010-0442)

An integer overflow flaw was found in the way PostgreSQL used to
calculate the size of the hash table for joined relations. An
authenticated database user could create a specially crafted SQL query
which could cause a temporary denial of service (postgres daemon
crash) or, potentially, execute arbitrary code with the privileges of
the database server. (CVE-2010-0733)

PostgreSQL improperly protected session-local state during the
execution of an index function by a database superuser during the
database maintenance operations. An authenticated database user could
use this flaw to elevate their privileges via specially crafted index
functions. (CVE-2009-4136)

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1005&L=scientific-linux-errata&T=0&P=1675
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47439bea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/19");
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
if (rpm_check(release:"SL3", reference:"rh-postgresql-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-contrib-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-devel-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-docs-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-jdbc-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-libs-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-pl-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-python-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-server-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-tcl-7.3.21-3")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-test-7.3.21-3")) flag++;

if (rpm_check(release:"SL4", reference:"postgresql-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-contrib-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-devel-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-docs-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-jdbc-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-libs-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-pl-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-python-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-server-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-tcl-7.4.29-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-test-7.4.29-1.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"postgresql-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.21-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.21-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
