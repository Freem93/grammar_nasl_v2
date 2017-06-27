#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60794);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-1169", "CVE-2010-1170");

  script_name(english:"Scientific Linux Security Update : postgresql84 on SL5.x i386/x86_64");
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
"A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Perl. If the PL/Perl procedural language was
registered on a particular database, an authenticated database user
running a specially crafted PL/Perl script could use this flaw to
bypass intended PL/Perl trusted mode restrictions, allowing them to
run arbitrary Perl scripts with the privileges of the database server.
(CVE-2010-1169)

A flaw was found in the way PostgreSQL enforced permission checks on
scripts written in PL/Tcl. If the PL/Tcl procedural language was
registered on a particular database, an authenticated database user
running aspecially crafted PL/Tcl script could use this flaw to bypass
intended PL/Tcl trusted mode restrictions, allowing them to run
arbitrary Tcl scripts with the privileges of the database server.
(CVE-2010-1170)

If the postgresql service is running, it will be automatically
restarted after installing this update.

NOTE1: postgresql84 and postgresql packages cannot be installed
concurrently on the same system, with the exception that the
postgresql-libs package can remain in place in parallel with
postgresql84. The postgresql-libs package contains client-side library
code to which existing applications may be linked. These libraries
will still work with the newer server.

NOTE2: As 8.4.x also has on-disk data format differences from 8.1.x,
it is not possible to upgrade an existing 8.1.x PostgreSQL database to
8.4.x merely by replacing the packages. Instead, first dump the
contents of the existing database using the pg_dumpall command, then
shut down the old server and remove the database files (under
/var/lib/pgsql/data). Next, remove the old packages and install the
new ones; start the new server; and finally restore the data from the
pg_dumpall output."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1005&L=scientific-linux-errata&T=0&P=1817
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66bbd078"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.4-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.4-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
