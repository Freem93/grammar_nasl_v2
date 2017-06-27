#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60906);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3433");

  script_name(english:"Scientific Linux Security Update : postgresql on SL6.x i386/x86_64");
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
PL/Perl andaPL/Tcl languages to modify the behavior of a SECURITY
DEFINER functionacreated by a different user. If the PL/Perl or PL/Tcl
language was used toaimplement a SECURITY DEFINER function, an
authenticated database user couldause a PL/Perl or PL/Tcl script to
modify the behavior of that functionaduring subsequent calls in the
same session. This would result in theamodified or injected code also
being executed with the privileges of theauser who created the
SECURITY DEFINER function, possibly leading to privilege escalation.
(CVE-2010-3433)

These updated postgresql packages upgrade PostgreSQL to version 8.4.5.
Refer to the PostgreSQL Release Notes for a list of changes :

http://www.postgresql.org/docs/8.4/static/release.html

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=3318
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f784ca3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/23");
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
if (rpm_check(release:"SL6", reference:"postgresql-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.5-1.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.5-1.el6_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
