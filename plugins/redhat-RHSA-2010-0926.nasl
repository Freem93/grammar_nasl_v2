#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0926. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50853);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/01/04 15:51:49 $");

  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021");
  script_bugtraq_id(45118);
  script_osvdb_id(69607, 69608, 69609, 69610);
  script_xref(name:"RHSA", value:"2010:0926");

  script_name(english:"RHEL 4 / 5 : krb5 (RHSA-2010:0926)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

Multiple checksum validation flaws were discovered in the MIT Kerberos
implementation. A remote attacker could use these flaws to tamper with
certain Kerberos protocol packets and, possibly, bypass authentication
mechanisms in certain configurations using Single-use Authentication
Mechanisms. (CVE-2010-1323)

Red Hat would like to thank the MIT Kerberos Team for reporting these
issues.

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct these issues. After installing the
updated packages, the krb5kdc daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1323.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/Kerberos/advisories/MITKRB5-SA-2010-007.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0926.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0926";
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
  if (rpm_check(release:"RHEL4", reference:"krb5-devel-1.3.4-62.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"krb5-libs-1.3.4-62.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"krb5-server-1.3.4-62.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"krb5-workstation-1.3.4-62.el4_8.3")) flag++;


  if (rpm_check(release:"RHEL5", reference:"krb5-devel-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", reference:"krb5-libs-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-workstation-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-workstation-1.6.1-36.el5_5.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-workstation-1.6.1-36.el5_5.6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
  }
}
