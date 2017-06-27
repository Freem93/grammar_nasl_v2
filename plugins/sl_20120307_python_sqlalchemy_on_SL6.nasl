#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61278);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/12 14:36:13 $");

  script_cve_id("CVE-2012-0805");

  script_name(english:"Scientific Linux Security Update : python-sqlalchemy on SL6.x");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SQLAlchemy is an Object Relational Mapper (ORM) that provides a
flexible, high-level interface to SQL databases.

It was discovered that SQLAlchemy did not sanitize values for the
limit and offset keywords for SQL select statements. If an application
using SQLAlchemy accepted values for these keywords, and did not
filter or sanitize them before passing them to SQLAlchemy, it could
allow an attacker to perform a SQL injection attack against the
application. (CVE-2012-0805)

All users of python-sqlalchemy are advised to upgrade to this updated
package, which contains a patch to correct this issue. All running
applications using SQLAlchemy must be restarted for this update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=985
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1484ce73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-sqlalchemy package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (rpm_check(release:"SL6", reference:"python-sqlalchemy-0.5.5-3.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
