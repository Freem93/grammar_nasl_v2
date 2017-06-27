#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0441. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76676);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2013-6445");
  script_bugtraq_id(67733);
  script_osvdb_id(45109);
  script_xref(name:"RHSA", value:"2014:0441");

  script_name(english:"RHEL 5 : MRG (RHSA-2014:0441)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Messaging component packages that fix one security issue,
several bugs, and add various enhancements are now available for Red
Hat Enterprise MRG 2.5 for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

MRG Messaging is a high-speed reliable messaging distribution for
Linux based on AMQP (Advanced Message Queuing Protocol), an open
protocol standard for enterprise messaging that is designed to make
mission critical messaging widely available as a standard service, and
to make enterprise messaging interoperable across platforms,
programming languages, and vendors. MRG Messaging includes an AMQP
0-10 messaging broker; AMQP 0-10 client libraries for C++, Java JMS,
and Python; as well as persistence libraries and management tools.

It was found that MRG Management Console (cumin) used the crypt(3)
DES-based hash function to hash passwords. DES-based hashing has known
weaknesses that allow an attacker to more easily recover plain text
passwords from hashes via brute-force guessing. An attacker able to
compromise a cumin user database could potentially use this flaw to
recover plain text passwords from the password hashes stored in that
database. (CVE-2013-6445)

Note: In deployments where user account information is stored in a
database managed by cumin, it is recommended that users change their
passwords after this update is applied.

This issue was discovered by Tomas Novacik of the Red Hat MRG
Quality Engineering team.

This update also fixes several bugs and adds enhancements.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

All users of the Messaging capabilities of Red Hat Enterprise MRG are
advised to upgrade to these updated packages, which resolve these
issues and add these enhancements. After installing the updated
packages, stop the cluster by either running 'service qpidd stop' on
all nodes, or 'qpid-cluster --all-stop' on any one of the cluster
nodes. Once stopped, restart the cluster with 'service qpidd start' on
all nodes for the update to take effect."
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
    value:"http://rhn.redhat.com/errata/RHSA-2014-0441.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?687515f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cumin and / or mrg-release packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0441";
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

  if (rpm_check(release:"RHEL5", reference:"cumin-0.1.5796-2.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mrg-release-2.5.0-1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cumin / mrg-release");
  }
}
