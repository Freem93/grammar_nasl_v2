#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1506. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78940);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2011-4316", "CVE-2012-0860", "CVE-2012-0861", "CVE-2012-2696", "CVE-2012-5516");
  script_bugtraq_id(56825);
  script_xref(name:"RHSA", value:"2012:1506");

  script_name(english:"RHEL 6 : Virtualization Manager (RHSA-2012:1506)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Enterprise Virtualization Manager 3.1 is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Enterprise Virtualization Manager is a visual tool for
centrally managing collections of virtual servers running Red Hat
Enterprise Linux and Microsoft Windows. This package also includes the
Red Hat Enterprise Virtualization Manager API, a set of scriptable
commands that give administrators the ability to perform queries and
operations on Red Hat Enterprise Virtualization Manager.

A flaw was found in the way Red Hat Enterprise Linux hosts were added
to the Red Hat Enterprise Virtualization environment. The Python
scripts needed to configure the host for Red Hat Enterprise
Virtualization were stored in the '/tmp/' directory and could be
pre-created by an attacker. A local, unprivileged user on the host to
be added to the Red Hat Enterprise Virtualization environment could
use this flaw to escalate their privileges. This update provides the
Red Hat Enterprise Virtualization Manager part of the fix. The
RHSA-2012:1508 VDSM update (Red Hat Enterprise Linux hosts) must also
be installed to completely fix this issue. (CVE-2012-0860)

A flaw was found in the way Red Hat Enterprise Linux and Red Hat
Enterprise Virtualization Hypervisor hosts were added to the Red Hat
Enterprise Virtualization environment. The Python scripts needed to
configure the host for Red Hat Enterprise Virtualization were
downloaded in an insecure way, that is, without properly validating
SSL certificates during HTTPS connections. An attacker on the local
network could use this flaw to conduct a man-in-the-middle attack,
potentially gaining root access to the host being added to the Red Hat
Enterprise Virtualization environment. This update provides the Red
Hat Enterprise Virtualization Manager part of the fix. The
RHSA-2012:1508 VDSM update (Red Hat Enterprise Linux hosts) or
RHSA-2012:1505 rhev-hypervisor6 update (Red Hat Enterprise
Virtualization Hypervisor hosts) must also be installed to completely
fix this issue. (CVE-2012-0861)

It was found that under certain conditions, Red Hat Enterprise
Virtualization Manager would fail to lock the screen on a virtual
machine between SPICE (Simple Protocol for Independent Computing
Environments) sessions. A user with access to a virtual machine in Red
Hat Enterprise Virtualization Manager could potentially exploit this
flaw to gain access to another user's unlocked desktop session.
(CVE-2011-4316)

It was found that Red Hat Enterprise Virtualization Manager did not
correctly pass wipe-after-delete when moving disks between storage
domains. This resulted in such disks not being securely deleted as
expected, potentially leading to information disclosure.
(CVE-2012-5516)

A flaw was found in the way the Red Hat Enterprise Virtualization
Manager back end checked the privileges of users making requests via
the SOAP and GWT APIs. An authenticated attacker able to issue queries
against Red Hat Enterprise Virtualization Manager could use this flaw
to query data that they should not have access to. (CVE-2012-2696)

These issues were discovered by Red Hat.

In addition to resolving the above security issues these updated Red
Hat Enterprise Virtualization Manager packages fix various bugs, and
add various enhancements.

Documentation for these bug fixes and enhancements is available in the
Technical Notes :

https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Enterprise_Virtualization/3.1/html/Technical_Notes/index.html

All Red Hat Enterprise Virtualization Manager users are advised to
upgrade to these updated packages which resolve these security issues,
fix these bugs, and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4316.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2696.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/docs/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1506.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-genericapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-notification-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-allinone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1506";
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
  if (rpm_exists(rpm:"rhevm-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-config-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-config-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-genericapi-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-genericapi-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-notification-service-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-notification-service-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-allinone-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-allinone-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-common-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-common-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.1.0-32.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.1.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.1.0-32.el6ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-config / rhevm-dbscripts / etc");
  }
}
