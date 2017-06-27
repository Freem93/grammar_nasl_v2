#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0515. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97792);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-9587");
  script_osvdb_id(149902, 149920, 149921, 149922, 149923);
  script_xref(name:"RHSA", value:"2017:0515");

  script_name(english:"RHEL 7 : ansible (RHSA-2017:0515)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ansible and ceph-ansible is now available for Red Hat
Storage Console 2.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The ceph-ansible package provides Ansible playbooks for installing,
maintaining, and upgrading Red Hat Ceph Storage.

Ansible is a simple model-driven configuration management, multi-node
deployment, and remote task execution system. Ansible works over SSH
and does not require any software or daemons to be installed on remote
nodes. Extension modules can be written in any language and are
transferred to managed machines automatically.

The following packages have been upgraded to a later upstream version:
ceph-installer (1.2.2), ansible (2.2.1.0), python-passlib (1.6.5),
ceph-ansible (2.1.9). (BZ#1405630)

Security Fix(es) :

* An input validation vulnerability was found in Ansible's handling of
data sent from client systems. An attacker with control over a client
system being managed by Ansible and the ability to send facts back to
the Ansible server could use this flaw to execute arbitrary code on
the Ansible server using the Ansible server privileges.
(CVE-2016-9587)

Bug Fix(es) :

* Previously, the ceph-ansible utility permanently disabled the swap
partition. With this update, ceph-ansible can no longer disable swap.
(BZ# 1364167)

* Previously, the ceph-ansible utility did not support adding
encrypted OSD nodes. As a consequence, an attempt to upgrade to a
newer, minor, or major version failed on encrypted OSD nodes. In
addition, Ansible returned the following error message during the disk
activation task :

mount: unknown filesystem type 'crypto_LUKS'

With this update, ceph-ansible supports adding encrypted OSD nodes,
and upgrading works as expected. (BZ#1366808)

* Due to a bug in the underlying source code, the ceph-ansible utility
in some cases failed on the copy roundep task. Consequently, the
installation process was unsuccessful. This bug has been fixed, and
the installation now proceeds as expected. (BZ#1382878)

* Previously, installation using the ceph-ansible utility failed on
the 'fix partitions gpt header or labels of the journal devices' task
in the ceph-osd role because of an empty variable. The underlying
source code has been modified, and the installation no longer fails in
this case. (BZ# 1400967)

* Previously, Red Hat Console Agent setup performed by the
ceph-ansible utility only supported installations by using the Content
Delivery Network (CDN). Installations with an ISO file or local Yum
repository failed. With this update, all installations are successful.
(BZ#1403576)

* Previously, the ceph-ansible utility was unable to purge a cluster
with encrypted OSD devices because the underlying ceph-disk utility
was unable to destroy the partition table on an encrypted device by
using the '--zap-disk' option. The underlying source code has been
fixed allowing ceph-disk to use the '--zap-disk' option on encrypted
devices. As a result, ceph-ansible can purge clusters with encrypted
OSD devices as expected. (BZ #1414647)

* Previously, during the creation of Ceph clusters with nodes that use
IPv6 addressing, ceph-ansible added the 'ms bind ipv6' key to the Ceph
configuration file, but it did not assign any value to it. This
behavior caused an error when parsing the configuration file after the
cluster creation. With this update, the 'ms bind ipv6' key is properly
set in the Ceph configuration file allowing for proper configuration
file parsing on clusters that use IPv6 addressing. (BZ#1419814)

Enhancement(s) :

* The ceph-ansible utility now supports the client role. This new role
enables you to install Ceph clients by using Ansible and deploy nodes
to run tests against the Ceph cluster. (BZ#1384622)

* The ceph-installer API now supports installation of OSD nodes that
have journals collocated on the same devices. (BZ#1412867)"
  );
  # https://access.redhat.com/documentation/en/red-hat-storage-console/2.0/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?753eacbe"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9587.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-passlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2017:0515";
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
  if (rpm_check(release:"RHEL7", reference:"ansible-2.2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ceph-ansible-2.1.9-1.el7scon")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ceph-installer-1.2.2-1.el7scon")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-passlib-1.6.5-1.1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / ceph-ansible / ceph-installer / python-passlib");
  }
}
