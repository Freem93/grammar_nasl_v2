#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1205. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78970);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-4157");
  script_bugtraq_id(62970);
  script_xref(name:"RHSA", value:"2013:1205");

  script_name(english:"RHEL 6 : Red Hat Storage 2.0 (RHSA-2013:1205)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat Storage 2.0 packages that fix multiple security
issues, various bugs, and add one enhancement are now available.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Storage is a software only, scale-out storage solution that
provides flexible and agile unstructured data storage for the
enterprise.

Multiple insecure temporary file creation flaws were found in Red Hat
Storage server. A local user on the Red Hat Storage server could use
these flaws to cause arbitrary files to be overwritten as the root
user via a symbolic link attack. (CVE-2013-4157)

These issues were discovered by Gowrishankar Rajaiyan of Red Hat and
Kurt Seifried of the Red Hat Security Response Team.

This update also fixes the following bugs :

* Previously, rolling upgrades on a volume caused some processes to
abort which led to a possible corruption of the volume. Yum update
aborts with a message to stop the volume during an update. Now, with
this update rolling upgrades is not supported and it is mandatory to
stop the volume before any 'yum update'. (BZ#998649)

* Installing or upgrading the gluster-swift-plugin RPM overwrites
/etc/swift configuration files. Hence, the customer configuration is
overwritten, causing data unavailability. Now, the RPM installs or
upgrades new configuration files with a non-conflicting extension and
customer configuration files are not overwritten, maintaining data
availability. (BZ #997940, BZ#1000423)

This update also adds the following enhancement :

* A new upgrade script has been added. When Red Hat Storage Server 2.1
is released, this script will help users upgrade and resubscribe their
Red Hat Storage Server 2.0 Update 6 systems to Red Hat Storage Server
2.1. (BZ# 1002872)

All users of Red Hat Storage are advised to upgrade to these updated
packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1205.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:appliance-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gluster-swift-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-geo-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/04");
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
  rhsa = "RHSA-2013:1205";
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
  if (rpm_check(release:"RHEL6", reference:"appliance-base-2.0.6.0-2.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gluster-swift-plugin-1.0-7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-debuginfo-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-devel-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-fuse-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-geo-replication-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-rdma-3.3.0.14rhs-1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glusterfs-server-3.3.0.14rhs-1.el6rhs")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "appliance-base / gluster-swift-plugin / glusterfs / etc");
  }
}
