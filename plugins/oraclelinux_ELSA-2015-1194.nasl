#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1194 and 
# Oracle Linux Security Advisory ELSA-2015-1194 respectively.
#

include("compat.inc");

if (description)
{
  script_id(84464);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/06 17:11:37 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_osvdb_id(122456, 122457, 122458);
  script_xref(name:"RHSA", value:"2015:1194");

  script_name(english:"Oracle Linux 6 / 7 : postgresql (ELSA-2015-1194)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1194 :

Updated postgresql packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A double-free flaw was found in the connection handling. An
unauthenticated attacker could exploit this flaw to crash the
PostgreSQL back end by disconnecting at approximately the same time as
the authentication time out is triggered. (CVE-2015-3165)

It was discovered that PostgreSQL did not properly check the return
values of certain standard library functions. If the system is in a
state that would cause the standard library functions to fail, for
example memory exhaustion, an authenticated user could exploit this
flaw to disclose partial memory contents or cause the GSSAPI
authentication to use an incorrect keytab file. (CVE-2015-3166)

It was discovered that the pgcrypto module could return different
error messages when decrypting certain data with an incorrect key.
This can help an authenticated user to launch a possible cryptographic
attack, although no suitable attack is currently known.
(CVE-2015-3167)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Benkocs Norbert Attila as the original
reporter of CVE-2015-3165 and Noah Misch as the original reporter of
CVE-2015-3166 and CVE-2015-3167.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-June/005184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-June/005185.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"postgresql-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-contrib-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-devel-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-docs-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-libs-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plperl-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-plpython-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-pltcl-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-server-8.4.20-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"postgresql-test-8.4.20-3.el6_6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-devel-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-docs-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-libs-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-server-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-test-9.2.13-1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.13-1.el7_1")) flag++;


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
