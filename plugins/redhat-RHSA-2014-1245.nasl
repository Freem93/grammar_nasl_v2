#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1245. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77698);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4344");
  script_osvdb_id(99508, 108751, 109389);
  script_xref(name:"RHSA", value:"2014:1245");

  script_name(english:"RHEL 5 : krb5 (RHSA-2014:1245)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues and two bugs
are now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Kerberos is an authentication system which allows clients and services
to authenticate to each other with the help of a trusted third party,
a Kerberos Key Distribution Center (KDC).

It was found that if a KDC served multiple realms, certain requests
could cause the setup_server_realm() function to dereference a NULL
pointer. A remote, unauthenticated attacker could use this flaw to
crash the KDC using a specially crafted request. (CVE-2013-1418,
CVE-2013-6800)

A NULL pointer dereference flaw was found in the MIT Kerberos SPNEGO
acceptor for continuation tokens. A remote, unauthenticated attacker
could use this flaw to crash a GSSAPI-enabled server application.
(CVE-2014-4344)

A buffer over-read flaw was found in the way MIT Kerberos handled
certain requests. A man-in-the-middle attacker with a valid Kerberos
ticket who is able to inject packets into a client or server
application's GSSAPI session could use this flaw to crash the
application. (CVE-2014-4341)

This update also fixes the following bugs :

* Prior to this update, the libkrb5 library occasionally attempted to
free already freed memory when encrypting credentials. As a
consequence, the calling process terminated unexpectedly with a
segmentation fault. With this update, libkrb5 frees memory correctly,
which allows the credentials to be encrypted appropriately and thus
prevents the mentioned crash. (BZ#1004632)

* Previously, when the krb5 client library was waiting for a response
from a server, the timeout variable in certain cases became a negative
number. Consequently, the client could enter a loop while checking for
responses. With this update, the client logic has been modified and
the described error no longer occurs. (BZ#1089732)

All krb5 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the krb5kdc daemon will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4344.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1245.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");
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
  rhsa = "RHSA-2014:1245";
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
  if (rpm_check(release:"RHEL5", reference:"krb5-debuginfo-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"krb5-devel-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"krb5-libs-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-ldap-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-ldap-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-ldap-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-workstation-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-workstation-1.6.1-78.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-workstation-1.6.1-78.el5")) flag++;

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
