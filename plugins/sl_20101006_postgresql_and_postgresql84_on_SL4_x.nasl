#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60862);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-3433");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL4.x, SL5.x i386/x86_64");
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
"It was discovered that a user could utilize the features of the
PL/Perl and PL/Tcl languages to modify the behavior of a SECURITY
DEFINER function created by a different user. If the PL/Perl or PL/Tcl
language was used to implement a SECURITY DEFINER function, an
authenticated database user could use a PL/Perl or PL/Tcl script to
modify the behavior of that function during subsequent calls in the
same session. This would result in the modified or injected code also
being executed with the privileges of the user who created the
SECURITY DEFINER function, possibly leading to privilege escalation.
(CVE-2010-3433)

For Scientific Linux 4, the updated postgresql packages upgrade
PostgreSQL to version 7.4.30.

For Scientific Linux 5, the updated postgresql packages upgrade
PostgreSQL to version 8.1.22, and the updated postgresql84 packages
upgrade PostgreSQL to version 8.4.5.

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=414
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ec49a99"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL4", reference:"postgresql-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-contrib-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-devel-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-docs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-jdbc-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-libs-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-pl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-python-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-server-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-tcl-7.4.30-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-test-7.4.30-1.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"postgresql-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.22-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.5-1.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.5-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
