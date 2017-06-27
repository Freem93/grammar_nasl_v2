#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60332);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-5925", "CVE-2007-5969");

  script_name(english:"Scientific Linux Security Update : mysql on SL5.x, SL4.x i386/x86_64");
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
"A flaw was found in a way MySQL handled symbolic links when database
tables were created with explicit 'DATA' and 'INDEX DIRECTORY'
options. An authenticated user could create a table that would
overwrite tables in other databases, causing destruction of data or
allowing the user to elevate privileges. (CVE-2007-5969)

A flaw was found in a way MySQL's InnoDB engine handled spatial
indexes. An authenticated user could create a table with spatial
indexes, which are not supported by the InnoDB engine, that would
cause the mysql daemon to crash when used. This issue only causes a
temporary denial of service, as the mysql daemon will be automatically
restarted after the crash. (CVE-2007-5925)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=2138
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e00bf093"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/18");
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
if (rpm_check(release:"SL4", cpu:"i386", reference:"mysql-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"mysql-4.1.20-3.RHEL4.1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"mysql-bench-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"mysql-bench-4.1.20-3.RHEL4.1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"mysql-devel-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"mysql-devel-4.1.20-3.RHEL4.1.el4.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"mysql-server-4.1.20-3.RHEL4.1.el4_6.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"mysql-server-4.1.20-3.RHEL4.1.el4.1")) flag++;

if (rpm_check(release:"SL5", reference:"mysql-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-bench-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-devel-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-server-5.0.22-2.2.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"mysql-test-5.0.22-2.2.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
