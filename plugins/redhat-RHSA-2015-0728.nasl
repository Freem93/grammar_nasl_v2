#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0728. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82291);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2015-0283", "CVE-2015-1827");
  script_bugtraq_id(73376, 73377);
  script_xref(name:"RHSA", value:"2015:0728");

  script_name(english:"RHEL 7 : ipa and slapi-nis (RHSA-2015:0728)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa and slapi-nis packages that fix two security issues and
several bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management is a centralized authentication, identity
management, and authorization solution for both traditional and
cloud-based enterprise environments. It integrates components of the
Red Hat Directory Server, MIT Kerberos, Red Hat Certificate System,
NTP, and DNS. It provides web browser and command-line interfaces. Its
administration tools allow an administrator to quickly install, set
up, and administer a group of domain controllers to meet the
authentication and identity management requirements of large-scale
Linux and UNIX deployments.

The ipa component provides centrally managed Identity, Policy, and
Audit. The slapi-nis component provides NIS Server and Schema
Compatibility plug-ins for Directory Server.

It was discovered that the IPA extdom Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for a list of groups for a user that belongs to
a large number of groups would cause a Directory Server to crash.
(CVE-2015-1827)

It was discovered that the slapi-nis Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for information about a group with many
members, or a request for a user that belongs to a large number of
groups, would cause a Directory Server to enter an infinite loop and
consume an excessive amount of CPU time. (CVE-2015-0283)

These issues were discovered by Sumit Bose of Red Hat.

This update fixes the following bugs :

* Previously, users of IdM were not properly granted the default
permission to read the 'facsimiletelephonenumber' user attribute. This
update adds 'facsimiletelephonenumber' to the Access Control
Instruction (ACI) for user data, which makes the attribute readable to
authenticated users as expected. (BZ#1198430)

* Prior to this update, when a DNS zone was saved in an LDAP database
without a dot character (.) at the end, internal DNS commands and
operations, such as dnsrecord-* or dnszone-*, failed. With this
update, DNS commands always supply the DNS zone with a dot character
at the end, which prevents the described problem. (BZ#1198431)

* After a full-server IdM restore operation, the restored server in
some cases contained invalid data. In addition, if the restored server
was used to reinitialize a replica, the replica then contained invalid
data as well. To fix this problem, the IdM API is now created
correctly during the restore operation, and *.ldif files are not
skipped during the removal of RUV data. As a result, the restored
server and its replica no longer contain invalid data. (BZ#1199060)

* Previously, a deadlock in some cases occurred during an IdM upgrade,
which could cause the IdM server to become unresponsive. With this
update, the Schema Compatibility plug-in has been adjusted not to
parse the subtree that contains the configuration of the DNA plug-in,
which prevents this deadlock from triggering. (BZ#1199128)

* When using the extdom plug-in of IdM to handle large groups, user
lookups and group lookups previously failed due to insufficient buffer
size. With this update, the getgrgid_r() call gradually increases the
buffer length if needed, and the described failure of extdom thus no
longer occurs. (BZ#1203204)

Users of ipa and slapi-nis are advised to upgrade to these updated
packages, which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1827.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0728.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slapi-nis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0728";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-admintools-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-client-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-debuginfo-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-debuginfo-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-python-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.el7_1.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"slapi-nis-0.54-3.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"slapi-nis-debuginfo-0.54-3.el7_1")) flag++;


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
