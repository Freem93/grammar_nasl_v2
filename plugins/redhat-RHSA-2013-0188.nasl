#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0188. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63675);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-5484");
  script_bugtraq_id(57529);
  script_osvdb_id(89537);
  script_xref(name:"RHSA", value:"2013:0188");

  script_name(english:"RHEL 6 : ipa (RHSA-2013:0188)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Red Hat Identity Management is a centralized authentication, identity
management and authorization solution for both traditional and
cloud-based enterprise environments.

A weakness was found in the way IPA clients communicated with IPA
servers when initially attempting to join IPA domains. As there was no
secure way to provide the IPA server's Certificate Authority (CA)
certificate to the client during a join, the IPA client enrollment
process was susceptible to man-in-the-middle attacks. This flaw could
allow an attacker to obtain access to the IPA server using the
credentials provided by an IPA client, including administrative access
to the entire domain if the join was performed using an
administrator's credentials. (CVE-2012-5484)

Note: This weakness was only exposed during the initial client join to
the realm, because the IPA client did not yet have the CA certificate
of the server. Once an IPA client has joined the realm and has
obtained the CA certificate of the IPA server, all further
communication is secure. If a client were using the OTP (one-time
password) method to join to the realm, an attacker could only obtain
unprivileged access to the server (enough to only join the realm).

Red Hat would like to thank Petr Mensik for reporting this issue.

This update must be installed on both the IPA client and IPA server.
When this update has been applied to the client but not the server,
ipa-client-install, in unattended mode, will fail if you do not have
the correct CA certificate locally, noting that you must use the
'--force' option to insecurely obtain the certificate. In interactive
mode, the certificate will try to be obtained securely from LDAP. If
this fails, you will be prompted to insecurely download the
certificate via HTTP. In the same situation when using OTP, LDAP will
not be queried and you will be prompted to insecurely download the
certificate via HTTP.

Users of ipa are advised to upgrade to these updated packages, which
correct this issue. After installing the update, changes in LDAP are
handled by ipa-ldap-updater automatically and are effective
immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0188.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0188";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-admintools-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-admintools-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-admintools-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-client-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-client-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-client-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-debuginfo-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-debuginfo-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-debuginfo-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-python-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-python-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-python-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-selinux-2.2.0-17.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-selinux-2.2.0-17.el6_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
  }
}
