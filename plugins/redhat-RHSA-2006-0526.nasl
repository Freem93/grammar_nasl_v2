#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0526. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21595);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-0591", "CVE-2006-2313", "CVE-2006-2314");
  script_bugtraq_id(18092);
  script_osvdb_id(23005, 25730, 25731);
  script_xref(name:"RHSA", value:"2006:0526");

  script_name(english:"RHEL 3 / 4 : postgresql (RHSA-2006:0526)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security vulnerabilities
are now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A bug was found in the way PostgreSQL's PQescapeString function
escapes strings when operating in a multibyte character encoding. It
is possible for an attacker to provide an application a carefully
crafted string containing invalidly-encoded characters, which may be
improperly escaped, allowing the attacker to inject malicious SQL.
While this update fixes how PQescapeString operates, the PostgreSQL
server has also been modified to prevent such an attack occurring
through unpatched clients. (CVE-2006-2313, CVE-2006-2314). More
details about this issue are available in the linked PostgreSQL
technical documentation.

An integer signedness bug was found in the way PostgreSQL generated
password salts. The actual salt size is only half the size of the
expected salt, making the process of brute forcing password hashes
slightly easier. This update will not strengthen already existing
passwords, but all newly assigned passwords will have the proper salt
length. (CVE-2006-0591)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 7.4.13, which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-2313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-2314.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/techdocs.52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0526.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0526";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-contrib-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-devel-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-docs-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-jdbc-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-libs-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-pl-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-python-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-server-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-tcl-7.3.15-2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"rh-postgresql-test-7.3.15-2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-contrib-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-devel-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-docs-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-jdbc-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-libs-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-pl-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-python-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-server-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-tcl-7.4.13-2.RHEL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"postgresql-test-7.4.13-2.RHEL4.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
  }
}
