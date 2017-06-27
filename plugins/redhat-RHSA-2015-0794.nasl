#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0794. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82656);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422");
  script_bugtraq_id(71679, 72494, 72495, 72496);
  script_osvdb_id(115960, 117920, 117921, 117922, 118567, 118568, 118569, 118570);
  script_xref(name:"RHSA", value:"2015:0794");

  script_name(english:"RHEL 6 : krb5 (RHSA-2015:0794)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Kerberos is a networked authentication system which allows clients and
servers to authenticate to each other with the help of a trusted third
party, the Kerberos KDC.

The following security issues are fixed with this release :

A use-after-free flaw was found in the way the MIT Kerberos
libgssapi_krb5 library processed valid context deletion tokens. An
attacker able to make an application using the GSS-API library
(libgssapi) could call the gss_process_context_token() function and
use this flaw to crash that application. (CVE-2014-5352)

If kadmind were used with an LDAP back end for the KDC database, a
remote, authenticated attacker who has the permissions to set the
password policy could crash kadmind by attempting to use a named
ticket policy object as a password policy for a principal.
(CVE-2014-5353)

It was found that the krb5_read_message() function of MIT Kerberos did
not correctly sanitize input, and could create invalid krb5_data
objects. A remote, unauthenticated attacker could use this flaw to
crash a Kerberos child process via a specially crafted request.
(CVE-2014-5355)

A double-free flaw was found in the way MIT Kerberos handled invalid
External Data Representation (XDR) data. An authenticated user could
use this flaw to crash the MIT Kerberos administration server
(kadmind), or other applications using Kerberos libraries, via
specially crafted XDR packets. (CVE-2014-9421)

It was found that the MIT Kerberos administration server (kadmind)
incorrectly accepted certain authentication requests for two-component
server principal names. A remote attacker able to acquire a key with a
particularly named principal (such as 'kad/x') could use this flaw to
impersonate any user to kadmind, and perform administrative actions as
that user. (CVE-2014-9422)

Red Hat would like to thank the MIT Kerberos project for reporting
CVE-2014-5352, CVE-2014-9421, and CVE-2014-9422. The MIT Kerberos
project acknowledges Nico Williams for assisting with the analysis of
CVE-2014-5352.

All krb5 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0794.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0794";
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
  if (rpm_check(release:"RHEL6", reference:"krb5-debuginfo-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-devel-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-libs-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-pkinit-openssl-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-pkinit-openssl-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-pkinit-openssl-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-server-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-server-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-server-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"krb5-server-ldap-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-workstation-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-workstation-1.10.3-37.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-workstation-1.10.3-37.el6_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit-openssl / etc");
  }
}
