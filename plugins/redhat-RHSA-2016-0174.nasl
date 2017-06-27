#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0174. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88746);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2015-7518");
  script_xref(name:"RHSA", value:"2016:0174");

  script_name(english:"RHEL 6 / 7 : Satellite 6.1.7 (RHSA-2016:0174)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Satellite 6.1 packages that fix one security issue, add one
enhancement, and fix several bugs are available for Satellite 6.1.7.

Red Hat Product Security has rated this update as having Moderate
Security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Satellite is a system management solution that allows
organizations to configure and maintain their systems without the
necessity to provide public Internet access to their servers or other
client systems. It performs provisioning and configuration management
of predefined standard operating environments.

A stored cross-site scripting (XSS) flaw was found in the smart class
parameters/variables field. By sending a specially crafted request to
Satellite, a remote, authenticated attacker could embed HTML content
into the stored data, allowing them to inject malicious content into
the web page that is used to view that data. (CVE-2015-7518)

This update also fixes the following bugs :

* New subscription rules for developer subscriptions caused manifest
imports into Satellite to fail. The subscription engine has been
updated to handle these new subscription rules correctly. (BZ#1301812)

* A heavy load on content synchronization caused tasks to appear as if
they had not stopped. The content engine has been updated to handle
these messages with varying amounts of load. (BZ#1300811)

* Deleted directories in the /var/lib/pulp/ directory caused errors
related to 'missing symlinks' during content synchronization. The code
has been updated to notice deleted directories, and recreate them as
necessary. (BZ#1288855, BZ#1276911)

* The networking API returned a JSON output which did not contain the
identifier of the interface. This data is critical for scripting, and
has been added to the API response. (BZ#1282539)

* When provisioning against Red Hat Enterprise Virtualization (RHEV),
the operating system information was not passed, causing provisioning
to fail. The interface to RHEV has been updated to resolve this bug.
(BZ#1279631)

* Incremental updates initiated from the command line were failing
with an 'ID not found' error. The command line interface has been
patched to provide the correct ID, thus fixing this bug. (BZ#1259057)

* Satellite used a large number of inodes when publishing a content.
The internal file handling has been improved to reduce the number of
symlinks and inodes required. (BZ#1244130)

* Provisioning on VMware with multiple NICs was not handling labels
correctly. The interface to VMware has been improved to handle this
situation correctly. (BZ#1197156)

* Previously, failed synchronization tasks on a Capsule which were not
reported correctly, and appeared as successful in the web UI. The
error handing logic has been improved to display the true state of the
task. (BZ#1215838)

* Satellite synchronized duplicate packages with the same epoch, name,
version, release, and architecture (ENVRA), but which were signed by
different checksums. This caused issues for clients attempting to
install from the repository. The code was updated to respect the
primary metadata, and only download a single package. (BZ#1132659)

Users of Red Hat Satellite are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7518.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-child");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kombu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0174";
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
  if (rpm_check(release:"RHEL6", reference:"candlepin-0.9.49.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.9.49.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-tomcat6-0.9.49.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-compute-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-debug-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-gce-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-libvirt-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-ovirt-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-postgresql-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-vmware-1.7.2.53-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-2.3.25-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-base-2.3.25-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-admin-client-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-child-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-common-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-nodes-parent-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-admin-extensions-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-plugins-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-tools-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-admin-extensions-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-handlers-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-rpm-plugins-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-selinux-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-server-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-kombu-3.0.24-11.pulp.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-agent-lib-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-bindings-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-client-lib-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-common-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-puppet-common-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-rpm-common-2.6.0.20-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-fog-1.24.1-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-katello-2.2.0.83-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_katello-0.0.7.21-1.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"candlepin-0.9.49.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-selinux-0.9.49.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-tomcat-0.9.49.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-compute-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-gce-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-libvirt-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ovirt-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-vmware-1.7.2.53-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-2.3.25-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-base-2.3.25-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-admin-client-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-nodes-child-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-nodes-common-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-nodes-parent-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-admin-extensions-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-plugins-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-tools-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-admin-extensions-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-handlers-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-plugins-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-selinux-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-server-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-kombu-3.0.24-11.pulp.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-agent-lib-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-bindings-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-client-lib-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-common-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-puppet-common-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-rpm-common-2.6.0.20-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-fog-1.24.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-katello-2.2.0.83-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-hammer_cli_katello-0.0.7.21-1.el7sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "candlepin / candlepin-selinux / candlepin-tomcat / etc");
  }
}
