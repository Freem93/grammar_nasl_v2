#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0440. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76675);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2012-6619", "CVE-2013-6445");
  script_bugtraq_id(67733);
  script_osvdb_id(45109);
  script_xref(name:"RHSA", value:"2014:0440");

  script_name(english:"RHEL 6 : MRG (RHSA-2014:0440)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Grid component packages that fix two security issues, multiple
bugs, and provide several enhancements are now available for Red Hat
Enterprise MRG 2.5 for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

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

A buffer over-read flaw was found in the way MongoDB handled BSON
data. A database user permitted to insert BSON data into a MongoDB
server could use this flaw to read server memory, potentially
disclosing sensitive data. (CVE-2012-6619)

Note: This update addresses CVE-2012-6619 by enabling the '--objcheck'
option in the /etc/mongodb.conf file. If you have edited this file,
the updated version will be stored as /etc/mongodb.conf.rpmnew, and
you will need to merge the changes into /etc/mongodb.conf manually.

It was found that MRG Management Console (cumin) used the crypt(3)
DES-based hash function to hash passwords. DES-based hashing has known
weaknesses that allow an attacker to recover plain text passwords from
hashes. An attacker able to compromise a cumin user database could
potentially use this flaw to recover plain text passwords from the
password hashes stored in that database. (CVE-2013-6445)

Note: In deployments where user account information is stored in a
database managed by cumin, it is recommended that users change their
passwords after this update is applied.

The CVE-2013-6445 issue was discovered by Tomas Novacik of the Red
Hat MRG Quality Engineering team.

These updated packages for Red Hat Enterprise Linux 6 also provide
numerous bug fixes and enhancements for the Grid component of Red Hat
Enterprise MRG. Space precludes documenting all of these changes in
this advisory. Refer to the Red Hat Enterprise MRG 2 Technical Notes
document, available shortly from the link in the References section,
for information on these changes.

All users of the Grid capabilities of Red Hat Enterprise MRG are
advised to upgrade to these updated packages, which correct these
issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6445.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae491241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0440.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
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
  rhsa = "RHSA-2014:0440";
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

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-aviary-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-aviary-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-classads-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-classads-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-cluster-resource-agent-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-cluster-resource-agent-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-debuginfo-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-debuginfo-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-deltacloud-gahp-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-kbdd-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-kbdd-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-plumage-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-plumage-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-qmf-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-qmf-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-vm-gahp-7.8.10-0.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cumin-0.1.5797-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-debuginfo-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-debuginfo-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-server-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-server-1.6.4-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mrg-release-2.5.0-1.el6")) flag++;

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
