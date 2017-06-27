#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2383. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86987);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:54 $");

  script_cve_id("CVE-2015-1867");
  script_osvdb_id(120610);
  script_xref(name:"RHSA", value:"2015:2383");

  script_name(english:"RHEL 7 : pacemaker (RHSA-2015:2383)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pacemaker packages that fix one security issue, several bugs,
and add two enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Pacemaker Resource Manager is a collection of technologies working
together to provide data integrity and the ability to maintain
application availability in the event of a failure.

A flaw was found in the way pacemaker, a cluster resource manager,
evaluated added nodes in certain situations. A user with read-only
access could potentially assign any other existing roles to themselves
and then add privileges to other users as well. (CVE-2015-1867)

The pacemaker packages have been upgraded to upstream version 1.1.13,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1234680)

This update also fixes the following bugs :

* When a Pacemaker cluster included an Apache resource, and Apache's
mod_systemd module was enabled, systemd rejected notifications sent by
Apache. As a consequence, a large number of errors in the following
format appeared in the system log :

Got notification message from PID XXXX, but reception only permitted
for PID YYYY

With this update, the lrmd daemon now unsets the 'NOTIFY_SOCKET'
variable in the described circumstances, and these error messages are
no longer logged. (BZ#1150184)

* Previously, specifying a remote guest node as a part of a group
resource in a Pacemaker cluster caused the node to stop working. This
update adds support for remote guests in Pacemaker group resources,
and the described problem no longer occurs. (BZ#1168637)

* When a resource in a Pacemaker cluster failed to start, Pacemaker
updated the resource's last failure time and incremented its fail
count even if the 'on-fail=ignore' option was used. This in some cases
caused unintended resource migrations when a resource start failure
occurred. Now, Pacemaker does not update the fail count when
'on-fail=ignore' is used. As a result, the failure is displayed in the
cluster status output, but is properly ignored and thus does not cause
resource migration. (BZ#1200849)

* Previously, Pacemaker supported semicolon characters (';') as
delimiters when parsing the pcmk_host_map string, but not when parsing
the pcmk_host_list string. To ensure consistent user experience,
semicolons are now supported as delimiters for parsing pcmk_host_list,
as well. (BZ#1206232)

In addition, this update adds the following enhancements :

* If a Pacemaker location constraint has the
'resource-discovery=never' option, Pacemaker now does not attempt to
determine whether a specified service is running on the specified
node. In addition, if multiple location constraints for a given
resource specify 'resource-discovery=exclusive', then Pacemaker
attempts resource discovery only on the nodes specified in those
constraints. This allows Pacemaker to skip resource discovery on nodes
where attempting the operation would lead to error or other
undesirable behavior. (BZ#1108853)

* The procedure of configuring fencing for redundant power supplies
has been simplified in order to prevent multiple nodes accessing
cluster resources at the same time and thus causing data corruption.
For further information, see the 'Fencing: Configuring STONITH'
chapter of the High Availability Add-On Reference manual. (BZ#1206647)

* The output of the 'crm_mon' and 'pcs_status' commands has been
modified to be clearer and more concise, and thus easier to read when
reporting the status of a Pacemaker cluster with a large number of
remote nodes and cloned resources. (BZ#1115840)

All pacemaker users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2383.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
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
  rhsa = "RHSA-2015:2383";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-cluster-libs-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-debuginfo-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-libs-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-libs-devel-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.13-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.13-10.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
  }
}
