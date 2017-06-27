#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70705);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/02 00:50:39 $");

  script_cve_id("CVE-2013-0255", "CVE-2013-1900");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL5.x, SL6.x i386/x86_64");
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
"An array index error, leading to a heap-based out-of-bounds buffer
read flaw, was found in the way PostgreSQL performed certain error
processing using enumeration types. An unprivileged database user
could issue a specially crafted SQL query that, when processed by the
server component of the PostgreSQL service, would lead to a denial of
service (daemon crash) or disclosure of certain portions of server
memory. (CVE-2013-0255)

A flaw was found in the way the pgcrypto contrib module of PostgreSQL
(re)initialized its internal random number generator. This could lead
to random numbers with less bits of entropy being used by certain
pgcrypto functions, possibly allowing an attacker to conduct other
attacks. (CVE-2013-1900)

These updated packages upgrade PostgreSQL to version 8.4.18, which
fixes these issues as well as several non-security issues. Refer to
the PostgreSQL Release Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release-8-4-18.html

After installing this update, it is advisable to rebuild, using the
REINDEX command, Generalized Search Tree (GiST) indexes that meet one
or more of the following conditions :

    - GiST indexes on box, polygon, circle, or point columns

    - GiST indexes for variable-width data types, that is
      text, bytea, bit, and numeric

    - GiST multi-column indexes

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=3018
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bacd7e6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release-8-4-18.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-debuginfo-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.18-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.18-1.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"postgresql-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.18-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.18-1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
