#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1255. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77741);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-4345");
  script_bugtraq_id(69168);
  script_osvdb_id(109908);
  script_xref(name:"RHSA", value:"2014:1255");

  script_name(english:"RHEL 5 : krb5 (RHSA-2014:1255)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Kerberos is an authentication system which allows clients and services
to authenticate to each other with the help of a trusted third party,
a Kerberos Key Distribution Center (KDC).

A buffer overflow was found in the KADM5 administration server
(kadmind) when it was used with an LDAP back end for the KDC database.
A remote, authenticated attacker could potentially use this flaw to
execute arbitrary code on the system running kadmind. (CVE-2014-4345)

All krb5 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the krb5kdc and kadmind daemons will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1255.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1255";
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
  if (rpm_check(release:"RHEL5", reference:"krb5-debuginfo-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"krb5-devel-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"krb5-libs-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-ldap-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-ldap-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-ldap-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-workstation-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-workstation-1.6.1-80.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-workstation-1.6.1-80.el5_11")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-server / etc");
  }
}
