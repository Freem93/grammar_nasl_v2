#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60675);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2007-6600", "CVE-2009-0922", "CVE-2009-3230");

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
"CVE-2009-0922 postgresql: potential DoS due to conversion functions

CVE-2009-3230 postgresql: SQL privilege escalation, incomplete fix for

CVE-2007-6600

It was discovered that the upstream patch for CVE-2007-6600 included
in the Scientific Linux did not include protection against misuse of
the RESET ROLE and RESET SESSION AUTHORIZATION commands. An
authenticated user could use this flaw to install malicious code that
would later execute with superuser privileges. (CVE-2009-3230)

A flaw was found in the way PostgreSQL handled encoding conversion. A
remote, authenticated user could trigger an encoding conversion
failure, possibly leading to a temporary denial of service. Note: To
exploit this issue, a locale and client encoding for which specific
messages fail to translate must be selected (the availability of these
is determined by an administrator-defined locale setting).
(CVE-2009-0922)

Note: For Scientific Linux 4, this update upgrades PostgreSQL to
version 7.4.26. For Scientific Linux 5, this update upgrades
PostgreSQL to version 8.1.18. Refer to the PostgreSQL Release Notes
for a list of changes :

http://www.postgresql.org/docs/7.4/static/release.html
http://www.postgresql.org/docs/8.1/static/release.html

If the postgresql service is running, it will be automatically
restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=928
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a45244e9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/7.4/static/release.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.1/static/release.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
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
if (rpm_check(release:"SL3", reference:"rh-postgresql-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-contrib-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-devel-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-docs-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-jdbc-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-libs-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-pl-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-python-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-server-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-tcl-7.3.21-2")) flag++;
if (rpm_check(release:"SL3", reference:"rh-postgresql-test-7.3.21-2")) flag++;

if (rpm_check(release:"SL4", reference:"postgresql-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-contrib-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-devel-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-docs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-jdbc-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-libs-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-pl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-python-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-server-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-tcl-7.4.26-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-test-7.4.26-1.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"postgresql-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-contrib-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-devel-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-docs-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-libs-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-pl-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-python-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-server-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-tcl-8.1.18-2.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"postgresql-test-8.1.18-2.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
