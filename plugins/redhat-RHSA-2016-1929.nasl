#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1929. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93681);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:46:32 $");

  script_cve_id("CVE-2016-4443");
  script_osvdb_id(143797);
  script_xref(name:"RHSA", value:"2016:1929");

  script_name(english:"RHEL 6 : Virtualization Manager (RHSA-2016:1929)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for org.ovirt.engine-root is now available for RHEV Manager
version 3.6.

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

* A flaw was found in RHEV Manager, where it wrote sensitive data to
the engine-setup log file. A local attacker could exploit this flaw to
view sensitive information such as encryption keys and certificates
(which could then be used to steal other sensitive information such as
passwords). (CVE-2016-4443)

This issue was discovered by Simone Tiraboschi (Red Hat).

Bug Fix(es) :

* With this update, users are now warned to set the system in global
maintenance mode before running the engine-setup command. This is
because data corruption may occur if the engine-setup command is run
without setting the system into global maintenance mode. This update
means that the user is warned and the setup will be aborted if the
system is not in global maintenance mode and the engine is running in
the hosted engine configuration. (BZ#1359844)

* Previously, the update of the compatibility version of a cluster
with many running virtual machines that are installed with the
guest-agent caused a deadlock that caused the update to fail. In some
cases, these clusters could not be upgraded to a newer compatibility
version. Now, the deadlock in the database has been prevented so that
a cluster with many running virtual machines that are installed with
the guest-agent can be upgraded to newer compatibility version.
(BZ#1369415)

* Previously, a virtual machine with a null CPU profile id stored in
the database caused a NPE when editing the virtual machine. Now, a
virtual machine with a null CPU profile id stored in the database is
correctly handled and the virtual machine can be edited. (BZ#1373090)

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
(BZ#1359767)

* Previously, recently added logs that printed the amount of virtual
machines running on a host were excessively written to the log file.
Now, the frequency of these log have been reduced by printing them
only upon a change in the number of virtual machines running on the
host. (BZ#1367519)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1929.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/23");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1929";
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
  if (rpm_exists(rpm:"rhevm-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-javadoc-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-javadoc-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-lib-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-lib-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-base-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-base-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-common-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-common-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-vmconsole-proxy-helper-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-vmconsole-proxy-helper-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-websocket-proxy-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-websocket-proxy-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-backup-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-backup-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-vmconsole-proxy-helper-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-vmconsole-proxy-helper-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.6.9.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-websocket-proxy-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-websocket-proxy-3.6.9.2-0.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-dbscripts / rhevm-extensions-api-impl / etc");
  }
}
