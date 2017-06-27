#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0347. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89097);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-0773");
  script_osvdb_id(134458);
  script_xref(name:"RHSA", value:"2016:0347");

  script_name(english:"RHEL 6 : postgresql (RHSA-2016:0347)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the PostgreSQL handling code for regular expressions. A
remote attacker could use a specially crafted regular expression to
cause PostgreSQL to crash or possibly execute arbitrary code.
(CVE-2016-0773)

Red Hat would like to thank PostgreSQL upstream for reporting this
issue. Upstream acknowledges Tom Lane and Greg Stark as the original
reporters.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news/1644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0347.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0347";
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
  if (rpm_check(release:"RHEL6", reference:"postgresql-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-contrib-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-contrib-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-contrib-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-debuginfo-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-devel-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-docs-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-docs-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-docs-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-libs-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plperl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plperl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plperl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plpython-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plpython-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plpython-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-pltcl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-pltcl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-pltcl-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-server-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-server-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-server-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-test-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-test-8.4.20-5.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-test-8.4.20-5.el6_7")) flag++;


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
