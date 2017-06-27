#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1475. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70696);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-0255", "CVE-2013-1900");
  script_osvdb_id(89935, 91961);
  script_xref(name:"RHSA", value:"2013:1475");

  script_name(english:"RHEL 5 / 6 : postgresql and postgresql84 (RHSA-2013:1475)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql and postgresql84 packages that fix two security
issues are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

An array index error, leading to a heap-based out-of-bounds buffer
read flaw, was found in the way PostgreSQL performed certain error
processing using enumeration types. An unprivileged database user
could issue a specially crafted SQL query that, when processed by the
server component of the PostgreSQL service, would lead to a denial of
service (daemon crash) or disclosure of certain portions of server
memory. (CVE-2013-0255)

A flaw was found in the way the pgcrypto contrib module of PostgreSQL
(re)initialized its internal random number generator. This could lead
to random numbers with less bits of entropy being used by certain
pgcrypto functions, possibly allowing an attacker to conduct other
attacks. (CVE-2013-1900)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Sumit Soni via Secunia SVCRP as the
original reporter of CVE-2013-0255, and Marko Kreen as the original
reporter of CVE-2013-1900.

These updated packages upgrade PostgreSQL to version 8.4.18, which
fixes these issues as well as several non-security issues. Refer to
the PostgreSQL Release Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release-8-4-18.html

After installing this update, it is advisable to rebuild, using the
REINDEX command, Generalized Search Tree (GiST) indexes that meet one
or more of the following conditions :

  - GiST indexes on box, polygon, circle, or point columns

  - GiST indexes for variable-width data types, that is
    text, bytea, bit, and numeric

  - GiST multi-column indexes

All PostgreSQL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0255.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1900.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release-8-4-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1475.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql84-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1475";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-contrib-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-contrib-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-contrib-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql84-debuginfo-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql84-devel-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-docs-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-docs-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-docs-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql84-libs-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-plperl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-plperl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-plperl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-plpython-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-plpython-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-plpython-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-pltcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-pltcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-pltcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-python-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-python-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-python-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-server-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-server-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-server-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-tcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-tcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-tcl-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql84-test-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql84-test-8.4.18-1.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql84-test-8.4.18-1.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", reference:"postgresql-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-contrib-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-contrib-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-contrib-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-debuginfo-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-devel-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-docs-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-docs-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-docs-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-libs-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plperl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plperl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plperl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plpython-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plpython-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plpython-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-pltcl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-pltcl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-pltcl-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-server-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-server-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-server-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-test-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-test-8.4.18-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-test-8.4.18-1.el6_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
  }
}
