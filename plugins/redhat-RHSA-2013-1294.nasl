#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1294. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76666);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4284");
  script_xref(name:"RHSA", value:"2013:1294");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:1294)");
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
Enterprise MRG 2.4 for Red Hat Enterprise Linux 6.

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

A denial of service flaw was found in the way cumin, a web management
console for MRG, processed certain Ajax update queries. A remote
attacker could use this flaw to issue a specially crafted HTTP
request, causing excessive use of CPU time and memory on the system.
(CVE-2013-4284)

The CVE-2013-4284 issue was discovered by Tomas Novacik of Red Hat.

These updated packages for Red Hat Enterprise Linux 6 provide numerous
enhancements and bug fixes for the Grid component of MRG. Some of the
most important enhancements include :

* Improved resource utilization with scheduler driven slot
partitioning * Enhanced integration with existing user & group
management technology, specifically allowing group and netgroup
specifications in HTCondor security policies * Addition of global job
priorities, allowing for priority to span scaled-out queues * Reduced
memory utilization per running job

Space precludes documenting all of these changes in this advisory.
Refer to the Red Hat Enterprise MRG 2 Technical Notes document,
available shortly from the link in the References section, for
information on these changes.

All users of the Grid capabilities of Red Hat Enterprise MRG are
advised to upgrade to these updated packages, which correct this
issue, and fix the bugs and add the enhancements noted in the Red Hat
Enterprise MRG 2 Technical Notes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4284.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae491241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1294.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-cluster-resource-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-deltacloud-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-plumage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1294";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-aviary-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-aviary-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-classads-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-classads-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-cluster-resource-agent-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-cluster-resource-agent-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-debuginfo-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-debuginfo-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-deltacloud-gahp-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-kbdd-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-kbdd-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-plumage-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-plumage-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-qmf-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-qmf-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-vm-gahp-7.8.9-0.5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cumin-0.1.5786-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mrg-release-2.4.0-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / etc");
  }
}
