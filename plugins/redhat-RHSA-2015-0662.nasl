#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0662. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81728);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2015-0203", "CVE-2015-0223", "CVE-2015-0224");
  script_bugtraq_id(72030, 72317, 72319);
  script_osvdb_id(117019, 117603);
  script_xref(name:"RHSA", value:"2015:0662");

  script_name(english:"RHEL 5 : qpid-cpp (RHSA-2015:0662)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qpid-cpp packages that fix multiple security issues and one
bug are now available for Red Hat Enterprise MRG Messaging 2.5 for Red
Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

The Qpid packages provide a message broker daemon that receives,
stores and routes messages using the open AMQP messaging protocol
along with run-time libraries for AMQP client applications developed
using Qpid C++. Clients exchange messages with an AMQP message broker
using the AMQP protocol.

It was discovered that the Qpid daemon (qpidd) did not restrict access
to anonymous users when the ANONYMOUS mechanism was disallowed.
(CVE-2015-0223)

Multiple flaws were found in the way the Qpid daemon (qpidd) processed
certain protocol sequences. An unauthenticated attacker able to send a
specially crafted protocol sequence set could use these flaws to crash
qpidd. (CVE-2015-0203, CVE-2015-0224)

Red Hat would like to thank the Apache Software Foundation for
reporting the CVE-2015-0203 issue. Upstream acknowledges G. Geshev
from MWR Labs as the original reporter.

This update also fixes the following bug :

* Prior to this update, because message purging was performed on a
timer thread, large purge events could have caused all other timer
tasks to be delayed. Because heartbeats were also driven by a timer on
this thread, this could have resulted in clients timing out because
they were not receiving heartbeats. The fix moves expired message
purging from the timer thread to a worker thread, which allow
long-running expired message purges to not affect timer tasks such as
the heartbeat timer. (BZ#1142833)

All users of Red Hat Enterprise MRG Messaging 2.5 for Red Hat
Enterprise Linux 5 are advised to upgrade to these updated packages,
which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0223.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0662.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0662";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-client-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-client-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-client-devel-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-client-devel-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-client-devel-docs-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-client-devel-docs-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-client-rdma-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-client-rdma-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-client-ssl-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-client-ssl-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-cluster-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-cluster-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-devel-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-devel-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-rdma-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-rdma-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-ssl-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-ssl-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-store-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-store-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"qpid-cpp-server-xml-0.18-38.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"qpid-cpp-server-xml-0.18-38.el5_10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qpid-cpp-client / qpid-cpp-client-devel / etc");
  }
}
