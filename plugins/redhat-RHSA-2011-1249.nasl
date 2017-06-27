#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1249. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76632);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/04 16:02:23 $");

  script_cve_id("CVE-2011-2925");
  script_osvdb_id(75217);
  script_xref(name:"RHSA", value:"2011:1249");

  script_name(english:"RHEL 5 : MRG (RHSA-2011:1249)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Grid component packages that fix one security issue, multiple
bugs, and add various enhancements are now available for Red Hat
Enterprise MRG 2.0 for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

MRG Grid provides high-throughput computing and enables enterprises to
achieve higher peak computing capacity as well as improved
infrastructure utilization by leveraging their existing technology to
build high performance grids. MRG Grid provides a job-queueing
mechanism, scheduling policy, and a priority scheme, as well as
resource monitoring and resource management. Users submit their jobs
to MRG Grid, where they are placed into a queue. MRG Grid then chooses
when and where to run the jobs based upon a policy, carefully monitors
their progress, and ultimately informs the user upon completion.

A flaw was discovered in Cumin where it would log broker
authentication credentials to the Cumin log file. A local user
exploiting this flaw could connect to the broker outside of Cumin's
control and perform certain operations such as scheduling jobs,
setting attributes on jobs, as well as holding, releasing or removing
jobs. The user could also use this to, depending on the defined ACLs
of the broker, manipulate message queues and other privileged
operations. (CVE-2011-2925)

In addition, these updated packages for Red Hat Enterprise Linux 5
provide numerous bug fixes and enhancements for the Grid component of
MRG. Some of the most important enhancements include :

* Expanded support of EC2 features, including EBS and VPC.

* Improved negotiation performance.

* Reduced shadow memory usage.

* Integrated configuration and management experience, including
real-time monitoring, diagnostics, and configuration templates.

Release Notes :

* When MRG Grid ran on a node with multiple network interfaces, it
tried to estimate the correct interface for its communications with
the remaining MRG Grid nodes. As a consequence, the node could have
failed to communicate with other parts of MRG Grid correctly if the
wrong interface had been chosen. As a workaround to this issue, MRG
Grid can be forced to use a specific network interface by setting the
NETWORK_INTERFACE parameter to the IP address of that interface. To
determine which interface was used by MRG Grid when it fails to
communicate with other parts of the grid, include the D_HOSTNAME
variable in the logging configuration of the corresponding daemon.
(BZ#728285)

* The remote configuration database requires an update to include
changes for MRG Grid version 2.0.1. But the database snapshot provided
with MRG only contains a basic configuration, and thus loading the
database snapshot would replace the existing pool configuration. To
solve this issue, the upgrade-wallaby-db tool which upgrades an
existing deployment's database has to be used. This tool can be
downloaded from the following page:
https://access.redhat.com/kb/docs/DOC-58404

* With this update, the Elastic Compute Cloud Grid ASCII Helper
Protocol (EC2 GAHP) is preferred over AMAZON GAHP. The
condor-ec2-enhanced-hooks package has been updated to detect the
correct GAHP for the EC2 Enhanced feature based upon what GAHPs are
available on the scheduler. To ensure that jobs are routed to the
proper resources, the 'set_gridresource = 'amazon'; \' setting should
be removed from all existing EC2 Enhanced routes in a MRG Grid's
configuration. (BZ#688717)

Space precludes documenting all of these changes in this advisory.
Refer to the Red Hat Enterprise MRG 2.0 Technical Notes document for
information on these changes :

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/2.0/html/
Technical_Notes/index.html

All users of the Grid capabilities of Red Hat Enterprise MRG 2.0 are
advised to upgrade to these updated packages, which resolve the issues
and add the enhancements noted in the Red Hat Enterprise MRG 2.0
Technical Notes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/2.0/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-58404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1249.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-job-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-low-latency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-base-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorec2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rhubarb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1249";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-aviary-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-aviary-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-classads-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-classads-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-ec2-enhanced-1.2-2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-ec2-enhanced-hooks-1.2-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-job-hooks-1.5-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-kbdd-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-kbdd-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-low-latency-1.2-2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-qmf-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-qmf-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-vm-gahp-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-vm-gahp-7.6.3-0.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-base-db-1.14-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-client-4.1-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-tools-4.1-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cumin-0.1.4916-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-condorec2e-1.2-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-condorutils-1.5-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-wallabyclient-4.1-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ruby-rhubarb-0.4.0-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ruby-wallaby-0.10.5-6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wallaby-0.10.5-6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wallaby-utils-0.10.5-6.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / condor-ec2-enhanced / etc");
  }
}
