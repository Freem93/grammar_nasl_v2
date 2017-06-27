#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2622. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87452);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-5233");
  script_osvdb_id(126930);
  script_xref(name:"RHSA", value:"2015:2622");

  script_name(english:"RHEL 6 / 7 : Satellite Server (RHSA-2015:2622)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Satellite 6.1 packages that fix one security issue, add one
enhancement, and fix several bugs are available for Satellite 6.1.5.

Red Hat Product Security has rated this update as having Moderate
Security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Satellite is a system management solution that allows
organizations to configure and maintain their systems without the
necessity to provide public Internet access to their servers or other
client systems. It performs provisioning and configuration management
of predefined standard operating environments.

The following security issue is addressed with this release :

Satellite failed to properly enforce permissions on the show and
destroy actions for reports. This could lead to an authenticated user
with show and/or destroy report permissions being able to view and/or
delete any reports held in Foreman. (CVE-2015-5233)

In addition, this update adds the following enhancement :

* Satellite 6 has been enhanced with the PXE-Less Discovery feature.
This feature supports the use of a single ISO to provision machines
against specific host groups. The users can provide the network
information so that the host does not need to be created on Satellite
in advance and DHCP does not need to be used. (BZ#1258061)

This update also fixes the following bugs :

* The installer was not processing the '\' character correctly,
leading to failed installations using proxies. This character is now
handled correctly, improving the installation experience. (BZ#1180637)

* Help text provided by the installer had a typo which has now been
fixed. (BZ#1209139)

* The hammer container list command did not provide the container ID.
This data is now provided. (BZ#1230915)

* Repository Sync Tasks in the UI were reported as successful if there
was an unhandled exception in the code. These exceptions are now
handled correctly, and the correct status is reported. (BZ#1246054)

* The installer would remove the dhcpd.conf even if the installer was
told not to. This would remove users' configurations. The installer
has been updated to not manage this file unless requested.
(BZ#1247397)

* The history diff page for templates was opening two pages when only
one was required. The duplicate page is no longer opened. (BZ#1254909)

* During provisioning, the default root password was not used when a
hostgroup had a blank string for the root password. Since the UI can
not set an empty value, the code was updated to cause either no or an
empty root password to use the default. (BZ#1255021)

* Multi selection was not working for discovered hosts. This feature
is now working. (BZ#1258521)

* When there is a mac address conflict, discovered hosts to not change
their state to 'Built.' The code has been updated to handle this case.
(BZ#1258578)

* Deleting a lifecycle environment would fail with a 'dependent hosts'
error. This was due to an incorrect mapping between environments and
hosts. This mapping has been fixed, and the environments can be
deleted. (BZ#1269441)

* There were performance issues in package installations. The speed of
this action has been improved (BZ#1276443, BZ#1269509, BZ#1277269)

* Synchronization tasks seemed to be randomly stuck to do timeouts.
The locking in the qpid code has been improved to keep these tasks
from getting stuck (BZ#1279502)

* This change enables users of CloudForms 4.0 to proxy Red Hat
Insights requests through Satellite. The Satellite can now act as a
proxy for both CloudForms 4.0 and Satellite-only use cases.
(BZ#1276676)

Users of Red Hat Satellite are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5233.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libqpid-dispatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nectar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-redhat_access_lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_docker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2622";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"katello-service") || rpm_exists(release:"RHEL7", rpm:"katello-service"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL6", reference:"foreman-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-compute-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-debug-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-discovery-image-3.0.5-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-gce-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-libvirt-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-ovirt-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-postgresql-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-proxy-1.7.2.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-vmware-1.7.2.49-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gofer-2.6.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-agent-2.2.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-2.3.22-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-base-2.3.22-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libqpid-dispatch-0.4-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-2.6.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-proton-2.6.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-gofer-qpid-2.6.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-nectar-1.3.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-qpid-0.30-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-proton-0.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-0.4-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-router-0.4-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-tools-0.4-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-c-0.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman-redhat_access-0.2.4-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_bootdisk-4.0.2.14-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-foreman_discovery-2.0.0.23-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-katello-2.2.0.77-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-redhat_access_lib-0.0.6-1.el6_6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_docker-0.0.3.10-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hammer_cli_foreman_docker-doc-0.0.3.10-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-newt-0.9.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-newt-debuginfo-0.9.6-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_discovery-1.0.3-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_discovery_image-1.0.5-3.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"foreman-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-compute-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-discovery-image-3.0.5-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-gce-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-libvirt-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ovirt-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-1.7.2.7-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-vmware-1.7.2.49-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gofer-2.6.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-agent-2.2.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-2.3.22-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-base-2.3.22-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libqpid-dispatch-0.4-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-2.6.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-proton-2.6.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-gofer-qpid-2.6.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-nectar-1.3.4-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-qpid-0.30-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-proton-0.9-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-0.4-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-router-0.4-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-tools-0.4-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-c-0.9-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.9-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-foreman-redhat_access-0.2.4-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-foreman_bootdisk-4.0.2.14-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-foreman_discovery-2.0.0.23-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-katello-2.2.0.77-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-redhat_access_lib-0.0.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-hammer_cli_foreman_docker-0.0.3.10-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-hammer_cli_foreman_docker-doc-0.0.3.10-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-newt-0.9.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-newt-debuginfo-0.9.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery-1.0.3-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery_image-1.0.5-3.el7sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "foreman / foreman-compute / foreman-debug / foreman-discovery-image / etc");
  }
}
