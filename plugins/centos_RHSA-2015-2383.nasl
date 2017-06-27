#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2383 and 
# CentOS Errata and Security Advisory 2015:2383 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87155);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-1867");
  script_osvdb_id(120610);
  script_xref(name:"RHSA", value:"2015:2383");

  script_name(english:"CentOS 7 : pacemaker (CESA-2015:2383)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b830bea6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cli-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cts-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-doc-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-libs-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.13-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-remote-1.1.13-10.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
