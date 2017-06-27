#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1002. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79112);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-3559");
  script_bugtraq_id(69174);
  script_xref(name:"RHSA", value:"2014:1002");

  script_name(english:"RHEL 6 : rhevm (RHSA-2014:1002)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhevm packages that fix one security issue are now available.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Enterprise Virtualization is a feature-rich server
virtualization management system that provides advanced capabilities
for managing Red Hat virtualization infrastructure for Servers and
Desktops.

It was found that the oVirt storage back end did not wipe memory
snapshots when VMs were deleted, even if wipe-after-delete (WAD) was
enabled for the VM's disks. A remote attacker with credentials to
create a new VM could use this flaw to potentially access the contents
of memory snapshots in an uninitialized storage volume, possibly
leading to the disclosure of sensitive information. (CVE-2014-3559)

This issue was discovered by Idan Shaby and Allon Mureinik of Red Hat.

All rhevm users are advised to upgrade to these updated packages,
which correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1002.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-allinone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
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
  rhsa = "RHSA-2014:1002";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_exists(rpm:"rhevm-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-lib-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-lib-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-base-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-base-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-allinone-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-allinone-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-common-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-common-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-websocket-proxy-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-websocket-proxy-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.4.1-0.31.el6ev")) flag++;
  if (rpm_exists(rpm:"rhevm-websocket-proxy-3.4.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-websocket-proxy-3.4.1-0.31.el6ev")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-dbscripts / rhevm-lib / rhevm-restapi / etc");
  }
}
