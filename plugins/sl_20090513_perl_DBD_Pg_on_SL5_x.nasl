#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60583);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0663", "CVE-2009-1341");

  script_name(english:"Scientific Linux Security Update : perl-DBD-Pg on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow flaw was discovered in the pg_getline
function implementation. If the pg_getline or getline functions read
large, untrusted records from a database, it could cause an
application using these functions to crash or, possibly, execute
arbitrary code. (CVE-2009-0663)

Note: After installing this update, pg_getline may return more data
than specified by its second argument, as this argument will be
ignored. This is consistent with current upstream behavior.
Previously, the length limit (the second argument) was not enforced,
allowing a buffer overflow.

A memory leak flaw was found in the function performing the de-quoting
of BYTEA type values acquired from a database. An attacker able to
cause an application using perl-DBD-Pg to perform a large number of
SQL queries returning BYTEA records, could cause the application to
use excessive amounts of memory or, possibly, crash. (CVE-2009-1341)

Applications using perl-DBD-Pg must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0905&L=scientific-linux-errata&T=0&P=1157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aee52d03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-DBD-Pg package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/13");
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
if (rpm_check(release:"SL5", reference:"perl-DBD-Pg-1.49-2.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
