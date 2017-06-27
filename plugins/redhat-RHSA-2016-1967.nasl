#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1967. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93805);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:46:32 $");

  script_cve_id("CVE-2016-5432");
  script_osvdb_id(144935);
  script_xref(name:"RHSA", value:"2016:1967");

  script_name(english:"RHEL 7 : org.ovirt.engine-root (RHSA-2016:1967)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for org.ovirt.engine-root is now available for RHEV Engine
version 4.0.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Red Hat Virtualization Manager is a centralized management
platform that allows system administrators to view and manage virtual
machines. The Manager provides a comprehensive range of features
including search capabilities, resource management, live migrations,
and virtual infrastructure provisioning.

The Manager is a JBoss Application Server application that provides
several interfaces through which the virtual environment can be
accessed and interacted with, including an Administration Portal, a
User Portal, and a Representational State Transfer (REST) Application
Programming Interface (API).

Security Fix(es) :

* It was found that the ovirt-engine-provisiondb utility did not
correctly sanitize the authentication details used with the
'--provision*db' options from the output before storing them in log
files. This could allow an attacker with read access to these log
files to obtain sensitive information such as passwords.
(CVE-2016-5432)

This issue was discovered by Yedidyah Bar David (Red Hat).

Bug Fix(es) :

* Previously, when checking permissions for a CPU profile, group
permissions were not considered. Users that were part of a group could
not assign a CPU profile and so could not start a virtual machine.
This was fixed by using PermissionDao and correct SQL functions when
checking permissions, so group permissions are now considered.
(BZ#1371888)

* Setting only one of the thresholds for power saving/evenly
distributed memory based balancing (high or low) can lead to
unexpected results. For example, when in power saving load balancing
the threshold for memory over utilized hosts was set with a value, and
the threshold for memory under utilized hosts was undefined thus
getting a default value of 0. All hosts were considered as under
utilized hosts and were chosen as sources for migration, but no host
was chosen as a destination for migration.

This has now been changed so that when the threshold for memory under
utilized host is undefined, it gets a default value of Long.MAX. Now,
when the threshold for memory over utilized hosts is set with a value,
and the threshold for memory under utilized host is undefined, only
over utilized hosts will be selected as sources for migration, and
destination hosts will be hosts that are not over utilized.
(BZ#1354281)

* This update ensures that Quality of Service (QoS) Storage values
that are sent to the VDSM service, are used by the VDSM and Memory
Overcommit Manager (MoM). The result is that QoS is live-applied on
virtual machines, and all MoM-related virtual machine changes are only
applied when the memory ballooning device is enabled on the virtual
machine. (BZ#1328731)

Enhancement(s) :

* Previously, it was possible to install incorrect versions of virtio
drivers, especially when running an older Windows operating system.
This sometimes caused the guest to terminate unexpectedly with a stop
error, also known as the 'Blue Screen of Death', if the particular
driver and Windows versions were incompatible. This update adds target
OS version information to driver files, which enables Windows to
automatically select the best driver when pointed to the root of the
virtio-win CD image. Installing an incompatible driver version
manually is also no longer possible, as Windows now presents the user
with an error message if installation is attempted. (BZ#1328181)

* With this release, Red Hat Virtualization now supports CephFS as a
POSIX storage domain. (BZ#1095615)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1967.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:1967";
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
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-backend-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-dbscripts-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-javadoc-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-lib-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-restapi-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-base-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-common-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-websocket-proxy-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-backup-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-userportal-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-vmconsole-proxy-helper-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-webadmin-portal-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-websocket-proxy-4.0.4.4-0.1.el7ev")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhevm-4.0.4.4-0.1.el7ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc");
  }
}
