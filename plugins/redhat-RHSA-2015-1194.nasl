#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1194. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84466);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_osvdb_id(122456, 122457, 122458);
  script_xref(name:"RHSA", value:"2015:1194");

  script_name(english:"RHEL 6 / 7 : postgresql (RHSA-2015:1194)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix three security issues are now
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
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1194.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1194";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", reference:"postgresql-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-contrib-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-contrib-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-contrib-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-debuginfo-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-devel-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-docs-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-docs-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-docs-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-libs-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plperl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plperl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plperl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plpython-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plpython-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plpython-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-pltcl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-pltcl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-pltcl-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-server-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-server-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-server-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-test-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-test-8.4.20-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-test-8.4.20-3.el6_6")) flag++;


  if (rpm_check(release:"RHEL7", reference:"postgresql-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-contrib-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-debuginfo-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-devel-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-docs-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-docs-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"postgresql-libs-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plperl-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-plpython-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-pltcl-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-server-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-server-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-test-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-test-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"postgresql-upgrade-9.2.13-1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.13-1.el7_1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
  }
}
