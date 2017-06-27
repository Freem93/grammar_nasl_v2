#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72569);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/19 11:50:45 $");

  script_cve_id("CVE-2013-3839", "CVE-2013-5807", "CVE-2013-5891", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0437");

  script_name(english:"Scientific Linux Security Update : mysql55-mysql on SL5.x i386/x86_64");
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
"A buffer overflow flaw was found in the way the MySQL command line
client tool (mysql) processed excessively long version strings. If a
user connected to a malicious MySQL server via the mysql client, the
server could use this flaw to crash the mysql client or, potentially,
execute arbitrary code as the user running the mysql client.
(CVE-2014-0001)

Upstream does not issue any more security advisories for the MySQL 5.0
packages (mysql-5.0.* and related packages). 

The only trusted way to upgrade from MySQL 5.0 to MySQL 5.5 is by
using MySQL 5.1 as an intermediate step. This is why the mysql51*
Software Collection packages are provided. Note that the MySQL 5.1
packages are not supported and are provided only for the purposes of
migrating to MySQL 5.5. You should not use the mysql51* packages on
any of your production systems.

Specific instructions for this migration are provided by the upstream
Deployment Guide.

After installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=2317
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25f0da0a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"mysql55-mysql-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-bench-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-debuginfo-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-devel-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-libs-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-server-5.5.36-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"mysql55-mysql-test-5.5.36-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
