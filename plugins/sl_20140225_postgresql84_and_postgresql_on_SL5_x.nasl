#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72699);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");

  script_name(english:"Scientific Linux Security Update : postgresql84 and postgresql on SL5.x, SL6.x i386/x86_64");
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
"Multiple stack-based buffer overflow flaws were found in the date/time
implementation of PostgreSQL. An authenticated database user could
provide a specially crafted date/time value that, when processed,
could cause PostgreSQL to crash or, potentially, execute arbitrary
code with the permissions of the user running PostgreSQL.
(CVE-2014-0063)

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in various type input functions in PostgreSQL.
An authenticated database user could possibly use these flaws to crash
PostgreSQL or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2014-0064)

Multiple potential buffer overflow flaws were found in PostgreSQL. An
authenticated database user could possibly use these flaws to crash
PostgreSQL or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2014-0065)

It was found that granting a SQL role to a database user in a
PostgreSQL database without specifying the 'ADMIN' option allowed the
grantee to remove other users from their granted role. An
authenticated database user could use this flaw to remove a user from
a SQL role which they were granted access to. (CVE-2014-0060)

A flaw was found in the validator functions provided by PostgreSQL's
procedural languages (PLs). An authenticated database user could
possibly use this flaw to escalate their privileges. (CVE-2014-0061)

A race condition was found in the way the CREATE INDEX command
performed multiple independent lookups of a table that had to be
indexed. An authenticated database user could possibly use this flaw
to escalate their privileges. (CVE-2014-0062)

It was found that the chkpass extension of PostgreSQL did not check
the return value of the crypt() function. An authenticated database
user could possibly use this flaw to crash PostgreSQL via a NULL
pointer dereference. (CVE-2014-0066)

These updated packages upgrade PostgreSQL to version 8.4.20, which
fixes these issues as well as several non-security issues. Refer to
the PostgreSQL Release Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release-8-4-19.html
http://www.postgresql.org/docs/8.4/static/release-8-4-20.html

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=2810
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48f6353d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release-8-4-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release-8-4-20.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-debuginfo-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.20-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.20-1.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"postgresql-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.20-1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.20-1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
