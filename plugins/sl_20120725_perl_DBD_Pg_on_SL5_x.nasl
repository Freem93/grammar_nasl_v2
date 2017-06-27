#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61372);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-1151");

  script_name(english:"Scientific Linux Security Update : perl-DBD-Pg on SL5.x, SL6.x i386/x86_64");
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
"Perl DBI is a database access Application Programming Interface (API)
for the Perl language. perl-DBD-Pg allows Perl applications to access
PostgreSQL database servers.

Two format string flaws were found in perl-DBD-Pg. A specially crafted
database warning or error message from a server could cause an
application using perl-DBD-Pg to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-1151)

All users of perl-DBD-Pg are advised to upgrade to this updated
package, which contains a backported patch to fix these issues.
Applications using perl-DBD-Pg must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=6126
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0453f4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected perl-DBD-Pg and / or perl-DBD-Pg-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/25");
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
if (rpm_check(release:"SL5", reference:"perl-DBD-Pg-1.49-4.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"perl-DBD-Pg-debuginfo-1.49-4.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"perl-DBD-Pg-2.15.1-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"perl-DBD-Pg-debuginfo-2.15.1-4.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
