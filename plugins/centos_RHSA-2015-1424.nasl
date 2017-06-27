#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1424 and 
# CentOS Errata and Security Advisory 2015:1424 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85020);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:12 $");

  script_cve_id("CVE-2015-1867");
  script_bugtraq_id(74231);
  script_osvdb_id(120610);
  script_xref(name:"RHSA", value:"2015:1424");

  script_name(english:"CentOS 6 : pacemaker (CESA-2015:1424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pacemaker packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 6.

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

This update also fixes the following bugs :

* Due to a race condition, nodes that gracefully shut down
occasionally had difficulty rejoining the cluster. As a consequence,
nodes could come online and be shut down again immediately by the
cluster. This bug has been fixed, and the 'shutdown' attribute is now
cleared properly. (BZ#1198638)

* Prior to this update, the pacemaker utility caused an unexpected
termination of the attrd daemon after a system update to Red Hat
Enterprise Linux 6.6. The bug has been fixed so that attrd no longer
crashes when pacemaker starts. (BZ#1205292)

* Previously, the access control list (ACL) of the pacemaker utility
allowed a role assignment to the Cluster Information Base (CIB) with a
read-only permission. With this update, ACL is enforced and can no
longer be bypassed by the user without the write permission, thus
fixing this bug. (BZ#1207621)

* Prior to this update, the ClusterMon (crm_mon) utility did not
trigger an external agent script with the '-E' parameter to monitor
the Cluster Information Base (CIB) when the pacemaker utility was
used. A patch has been provided to fix this bug, and crm_mon now calls
the agent script when the '-E' parameter is used. (BZ#1208896)

Users of pacemaker are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54ccebb5"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
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
if (rpm_check(release:"CentOS-6", reference:"pacemaker-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-cli-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-cluster-libs-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-cts-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-doc-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-libs-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-libs-devel-1.1.12-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pacemaker-remote-1.1.12-8.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
