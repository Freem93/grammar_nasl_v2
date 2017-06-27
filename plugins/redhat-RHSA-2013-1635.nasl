#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1635. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71012);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-0281");
  script_bugtraq_id(57965);
  script_osvdb_id(90240);
  script_xref(name:"RHSA", value:"2013:1635");

  script_name(english:"RHEL 6 : pacemaker (RHSA-2013:1635)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pacemaker packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Pacemaker is a high-availability cluster resource manager with a
powerful policy engine.

A denial of service flaw was found in the way Pacemaker performed
authentication and processing of remote connections in certain
circumstances. When Pacemaker was configured to allow remote Cluster
Information Base (CIB) configuration or resource management, a remote
attacker could use this flaw to cause Pacemaker to block indefinitely
(preventing it from serving other requests). (CVE-2013-0281)

Note: The default Pacemaker configuration in Red Hat Enterprise Linux
6 has the remote CIB management functionality disabled.

The pacemaker package has been upgraded to upstream version 1.1.10,
which provides a number of bug fixes and enhancements over the
previous version :

* Pacemaker no longer assumes unknown cman nodes are safely stopped.

* The core dump file now converts all exit codes into positive 'errno'
values.

* Pacemaker ensures a return to a stable state after too many fencing
failures, and initiates a shutdown if a node claimed to be fenced is
still active.

* The crm_error tool adds the ability to list and print error symbols.

* The crm_resource command allows individual resources to be reprobed,
and implements the '--ban' option for moving resources away from
nodes. The '--clear' option has replaced the '--unmove' option. Also,
crm_resource now supports OCF tracing when using the '--force' option.

* The IPC mechanism restores the ability for members of the haclient
group to connect to the cluster.

* The Policy Engine daemon allows active nodes in the current
membership to be fenced without quorum.

* Policy Engine now suppresses meaningless IDs when displaying
anonymous clone status, supports maintenance mode for a single node,
and correctly handles the recovered resources before they are operated
on.

* XML configuration files are now checked for non-printing characters
and replaced with their octal equivalent when exporting XML text.
Also, a more reliable buffer allocation strategy has been implemented
to prevent lockups.

(BZ#987355)

Additional bug fixes :

* The 'crm_resource --move' command was designed for atomic resources
and could not handle resources on clones, masters, or slaves present
on multiple nodes. Consequently, crm_resource could not obtain enough
information to move a resource and did not perform any action. The
'--ban' and '--clear' options have been added to allow the
administrator to instruct the cluster unambiguously. Clone, master,
and slave resources can now be navigated within the cluster as
expected. (BZ#902407)

* The hacluster user account did not have a user identification (UID)
or group identification (GID) number reserved on the system. Thus, UID
and GID values were picked randomly during the installation process.
The UID and GID number 189 was reserved for hacluster and is now used
consistently for all installations. (BZ#908450)

* Certain clusters used node host names that did not match the output
of the 'uname -n' command. Thus, the default node name used by the
crm_standby and crm_failcount commands was incorrect and caused the
cluster to ignore the update by the administrator. The crm_node
command is now used instead of the uname utility in helper scripts. As
a result, the cluster behaves as expected. (BZ#913093)

* Due to incorrect return code handling, internal recovery logic of
the crm_mon utility was not executed when a configuration updated
failed to apply, leading to an assertion failure. Return codes are now
checked correctly, and the recovery of an expected error state is now
handled transparently. (BZ#951371)

* cman's automatic unfencing feature failed when combined with
Pacemaker. Support for automated unfencing in Pacemaker has been
added, and the unwanted behavior no longer occurs. (BZ#996850)

All pacemaker users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0281.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1635.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
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
  rhsa = "RHSA-2013:1635";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cli-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cli-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cluster-libs-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-cts-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-cts-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-debuginfo-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-doc-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-doc-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-libs-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-libs-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-libs-devel-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pacemaker-remote-1.1.10-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pacemaker-remote-1.1.10-14.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
  }
}
