#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1533. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57014);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-3636");
  script_bugtraq_id(50930);
  script_osvdb_id(77568);
  script_xref(name:"RHSA", value:"2011:1533");

  script_name(english:"RHEL 6 : ipa (RHSA-2011:1533)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Identity Management is a centralized authentication, identity
management and authorization solution for both traditional and cloud
based enterprise environments. It integrates components of the Red Hat
Directory Server, MIT Kerberos, Red Hat Certificate System, NTP and
DNS. It provides web browser and command-line interfaces. Its
administration tools allow an administrator to quickly install, set
up, and administer a group of domain controllers to meet the
authentication and identity management requirements of large scale
Linux and UNIX deployments.

A Cross-Site Request Forgery (CSRF) flaw was found in Red Hat Identity
Management. If a remote attacker could trick a user, who was logged
into the management web interface, into visiting a specially crafted
URL, the attacker could perform Red Hat Identity Management
configuration changes with the privileges of the logged in user.
(CVE-2011-3636)

Due to the changes required to fix CVE-2011-3636, client tools will
need to be updated for client systems to communicate with updated Red
Hat Identity Management servers. New client systems will need to have
the updated ipa-client package installed to be enrolled. Already
enrolled client systems will need to have the updated certmonger
package installed to be able to renew their system certificate. Note
that system certificates are valid for two years by default.

Updated ipa-client and certmonger packages for Red Hat Enterprise
Linux 6 were released as part of Red Hat Enterprise Linux 6.2. Future
updates will provide updated packages for Red Hat Enterprise Linux 5.

This update includes several bug fixes. Space precludes documenting
all of these changes in this advisory. Users are directed to the Red
Hat Enterprise Linux 6.2 Technical Notes for information on the most
significant of these changes, linked to in the References section.

Users of Red Hat Identity Management should upgrade to these updated
packages, which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3636.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1533.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1533";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-admintools-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-admintools-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-admintools-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-client-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-client-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-client-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-debuginfo-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-debuginfo-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-debuginfo-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-python-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-python-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-python-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-selinux-2.1.3-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-selinux-2.1.3-9.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
  }
}
