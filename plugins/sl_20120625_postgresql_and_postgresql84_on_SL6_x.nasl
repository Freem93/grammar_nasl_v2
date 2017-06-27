#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61353);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/08/05 02:32:19 $");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655");

  script_name(english:"Scientific Linux Security Update : postgresql and postgresql84 on SL6.x i386/x86_64");
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
"PostgreSQL is an advanced object-relational database management system
(DBMS).

A flaw was found in the way the crypt() password hashing function from
the optional PostgreSQL pgcrypto contrib module performed password
transformation when used with the DES algorithm. If the password
string to be hashed contained the 0x80 byte value, the remainder of
the string was ignored when calculating the hash, significantly
reducing the password strength. This made brute-force guessing more
efficient as the whole password was not required to gain access to
protected resources. (CVE-2012-2143)

Note: With this update, the rest of the string is properly included in
the DES hash; therefore, any previously stored password values that
are affected by this issue will no longer match. In such cases, it
will be necessary for those stored password hashes to be updated.

A denial of service flaw was found in the way the PostgreSQL server
performed a user privileges check when applying SECURITY DEFINER or
SET attributes to a procedural language's (such as PL/Perl or
PL/Python) call handler function. A non-superuser database owner could
use this flaw to cause the PostgreSQL server to crash due to infinite
recursion. (CVE-2012-2655)

These updated packages upgrade PostgreSQL to version 8.4.12, which
fixes these issues as well as several non-security issues. Refer to
the PostgreSQL Release Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct these issues. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=1512
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63d2da11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/25");
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
if (rpm_check(release:"SL6", reference:"postgresql-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-contrib-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-debuginfo-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-devel-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-docs-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-libs-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plperl-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-plpython-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-pltcl-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-server-8.4.12-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"postgresql-test-8.4.12-1.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
