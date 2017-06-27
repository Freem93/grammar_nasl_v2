#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60950);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-4015");

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
"A stack-based buffer overflow flaw was found in the way PostgreSQL
processed certain tokens from a SQL query when the intarray module was
enabled on a particular database. An authenticated database user
running a specially crafted SQL query could use this flaw to cause a
temporary denial of service (postgres daemon crash) or, potentially,
execute arbitrary code with the privileges of the database server.
(CVE-2010-4015)

These updated postgresql84 packages upgrade PostgreSQL to version
8.4.7. Refer to the PostgreSQL Release Notes for a full list of
changes :

http://www.postgresql.org/docs/8.4/static/release.html

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=739
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?342eb651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/03");
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
if (rpm_check(release:"SL5", reference:"postgresql84-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-contrib-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-devel-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-docs-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-libs-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plperl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-plpython-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-pltcl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-python-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-server-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-tcl-8.4.7-1.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql84-test-8.4.7-1.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
