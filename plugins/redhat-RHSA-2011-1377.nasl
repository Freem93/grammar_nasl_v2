#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1377. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56533);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-2483");
  script_bugtraq_id(49241);
  script_osvdb_id(74742);
  script_xref(name:"RHSA", value:"2011:1377");

  script_name(english:"RHEL 4 / 5 / 6 : postgresql (RHSA-2011:1377)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A signedness issue was found in the way the crypt() function in the
PostgreSQL pgcrypto module handled 8-bit characters in passwords when
using Blowfish hashing. Up to three characters immediately preceding a
non-ASCII character (one with the high bit set) had no effect on the
hash result, thus shortening the effective password length. This made
brute-force guessing more efficient as several different passwords
were hashed to the same value. (CVE-2011-2483)

Note: Due to the CVE-2011-2483 fix, after installing this update some
users may not be able to log in to applications that store user
passwords, hashed with Blowfish using the PostgreSQL crypt() function,
in a back-end PostgreSQL database. Unsafe processing can be re-enabled
for specific passwords (allowing affected users to log in) by changing
their hash prefix to '$2x$'.

For Red Hat Enterprise Linux 6, the updated postgresql packages
upgrade PostgreSQL to version 8.4.9. Refer to the PostgreSQL Release
Notes for a full list of changes :

http://www.postgresql.org/docs/8.4/static/release.html

For Red Hat Enterprise Linux 4 and 5, the updated postgresql packages
contain a backported patch.

All PostgreSQL users are advised to upgrade to these updated packages,
which correct this issue. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/8.4/static/release.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1377.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1377";
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
  if (rpm_check(release:"RHEL4", reference:"postgresql-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-contrib-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-devel-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-docs-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-jdbc-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-libs-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-pl-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-python-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-server-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-tcl-7.4.30-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"postgresql-test-7.4.30-3.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-contrib-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-contrib-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-contrib-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql-devel-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-docs-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-docs-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-docs-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"postgresql-libs-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-pl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-pl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-pl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-python-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-python-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-python-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-server-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-server-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-server-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-tcl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-tcl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-tcl-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-test-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-test-8.1.23-1.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-test-8.1.23-1.el5_7.2")) flag++;


  if (rpm_check(release:"RHEL6", reference:"postgresql-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-contrib-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-contrib-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-contrib-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-debuginfo-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-devel-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-docs-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-docs-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-docs-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"postgresql-libs-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plperl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plperl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plperl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-plpython-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-plpython-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-plpython-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-pltcl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-pltcl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-pltcl-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-server-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-server-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-server-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postgresql-test-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postgresql-test-8.4.9-1.el6_1.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postgresql-test-8.4.9-1.el6_1.1")) flag++;


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
