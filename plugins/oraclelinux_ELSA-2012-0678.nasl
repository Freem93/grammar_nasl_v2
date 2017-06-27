#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0678 and 
# Oracle Linux Security Advisory ELSA-2012-0678 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68529);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868");
  script_bugtraq_id(52188);
  script_osvdb_id(79644, 79645, 79646);
  script_xref(name:"RHSA", value:"2012:0678");

  script_name(english:"Oracle Linux 5 / 6 : postgresql / postgresql84 (ELSA-2012-0678)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0678 :

Updated postgresql84 and postgresql packages that fix three security
issues are now available for Red Hat Enterprise Linux 5 and 6
respectively.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The pg_dump utility inserted object names literally into comments in
the SQL script it produces. An unprivileged database user could create
an object whose name includes a newline followed by a SQL command.
This SQL command might then be executed by a privileged user during
later restore of the backup dump, allowing privilege escalation.
(CVE-2012-0868)

When configured to do SSL certificate verification, PostgreSQL only
checked the first 31 characters of the certificate's Common Name
field. Depending on the configuration, this could allow an attacker to
impersonate a server or a client using a certificate from a trusted
Certificate Authority issued for a different name. (CVE-2012-0867)

CREATE TRIGGER did not do a permissions check on the trigger function
to be called. This could possibly allow an authenticated database user
to call a privileged trigger function on data of their choosing.
(CVE-2012-0866)

These updated packages upgrade PostgreSQL to version 8.4.11, which
fixes these issues as well as several data-corruption issues and
lesser non-security issues. Refer to the PostgreSQL Release Notes for
a full list of changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct these issues. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-May/002826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-May/002832.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql and / or postgresql84 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql84-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"postgresql84-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-contrib-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-devel-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-docs-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-libs-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-plperl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-plpython-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-pltcl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-python-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-server-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-tcl-8.4.11-1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"postgresql84-test-8.4.11-1.el5_8")) flag++;

if (rpm_check(release:"EL6", reference:"postgresql-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-contrib-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-devel-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-docs-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-libs-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plperl-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plpython-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-pltcl-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-server-8.4.11-1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-test-8.4.11-1.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
