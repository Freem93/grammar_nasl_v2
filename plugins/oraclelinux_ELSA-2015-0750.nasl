#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0750 and 
# Oracle Linux Security Advisory ELSA-2015-0750 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82465);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_osvdb_id(118033, 118035, 118036, 118037, 118038);
  script_xref(name:"RHSA", value:"2015:0750");

  script_name(english:"Oracle Linux 6 / 7 : postgresql (ELSA-2015-0750)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0750 :

Updated postgresql packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

An information leak flaw was found in the way the PostgreSQL database
server handled certain error messages. An authenticated database user
could possibly obtain the results of a query they did not have
privileges to execute by observing the constraint violation error
messages produced when the query was executed. (CVE-2014-8161)

A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a
specially crafted timestamp formatting template to cause PostgreSQL to
crash or, under certain conditions, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0241)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto
module. An authenticated database user could use this flaw to cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in the way PostgreSQL handled certain errors that
were generated during protocol synchronization. An authenticated
database user could use this flaw to inject queries into an existing
connection. (CVE-2015-0244)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Stephen Frost as the original reporter
of CVE-2014-8161; Andres Freund, Peter Geoghegan, Bernd Helmle, and
Noah Misch as the original reporters of CVE-2015-0241; Marko Tiikkaja
as the original reporter of CVE-2015-0243; and Emil Lenngren as the
original reporter of CVE-2015-0244.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004958.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"postgresql-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-contrib-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-devel-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-docs-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-libs-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plperl-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plpython-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-pltcl-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-server-8.4.20-2.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-test-8.4.20-2.el6_6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-devel-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-docs-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-libs-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-server-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-test-9.2.10-2.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.10-2.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
