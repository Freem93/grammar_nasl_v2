#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2290. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86980);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-3225");
  script_osvdb_id(123383);
  script_xref(name:"RHSA", value:"2015:2290");

  script_name(english:"RHEL 7 : pcs (RHSA-2015:2290)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated pcs package that fixes one security issue, several bugs,
and add various enhancements is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The pcs package provides a configuration tool for Corosync and
Pacemaker. It permits users to easily view, modify and create
Pacemaker based clusters. The pcs package includes Rack, which
provides a minimal interface between webservers that support Ruby and
Ruby frameworks.

A flaw was found in a way Rack processed parameters of incoming
requests. An attacker could use this flaw to send a crafted request
that would cause an application using Rack to crash. (CVE-2015-3225)

Red Hat would like to thank Ruby upstream developers for reporting
this. Upstream acknowledges Tomek Rabczak from the NCC Group as the
original reporter.

The pcs package has been upgraded to upstream version 0.9.143, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1198265)

The following enhancements are described in more detail in the Red Hat
Enterprise Linux 7.2 Release Notes, linked to from the References
section :

* The pcs resource move and pcs resource ban commands now display a
warning message to clarify the commands' behavior (BZ#1201452)

* New command to move a Pacemaker resource to its preferred node
(BZ#1122818)

This update also fixes the following bugs :

* Before this update, a bug caused location, ordering, and colocation
constraints related to a resource group to be removed when removing
any resource from that group. This bug has been fixed, and the
constraints are now preserved until the group has no resources left,
and is removed. (BZ#1158537)

* Previously, when a user disabled a resource clone or multi-state
resource, and then later enabled a primitive resource within it, the
clone or multi-state resource remained disabled. With this update,
enabling a resource within a disabled clone or multi-state resource
enables it. (BZ#1218979)

* When the web UI displayed a list of resource attributes, a bug
caused the list to be truncated at the first '=' character. This
update fixes the bug and now the web UI displays lists of resource
attributes correctly. (BZ#1243579)

* The documentation for the 'pcs stonith confirm' command was not
clear. This could lead to incorrect usage of the command, which could
in turn cause data corruption. With this update, the documentation has
been improved and the 'pcs stonith confirm' command is now more
clearly explained. (BZ#1245264)

* Previously, if there were any unauthenticated nodes, creating a new
cluster, adding a node to an existing cluster, or adding a cluster to
the web UI failed with the message 'Node is not authenticated'. With
this update, when the web UI detects a problem with authentication,
the web UI displays a dialog to authenticate nodes as necessary.
(BZ#1158569)

* Previously, the web UI displayed only primitive resources. Thus
there was no way to set attributes, constraints and other properties
separately for a parent resource and a child resource. This has now
been fixed, and resources are displayed in a tree structure, meaning
all resource elements can be viewed and edited independently.
(BZ#1189857)

In addition, this update adds the following enhancements :

* A dashboard has been added which shows the status of clusters in the
web UI. Previously, it was not possible to view all important
information about clusters in one place. Now, a dashboard showing the
status of clusters has been added to the main page of the web UI.
(BZ#1158566)

* With this update, the pcsd daemon automatically synchronizes pcsd
configuration across a cluster. This enables the web UI to be run from
any node, allowing management even if any particular node is down.
(BZ#1158577)

* The web UI can now be used to set permissions for users and groups
on a cluster. This allows users and groups to have their access
restricted to certain operations on certain clusters. (BZ#1158571)

All pcs users are advised to upgrade to this updated package, which
corrects these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3225.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4086253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2290.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcs and / or pcs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcs-debuginfo");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2290";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pcs-0.9.143-15.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pcs-debuginfo-0.9.143-15.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcs / pcs-debuginfo");
  }
}
