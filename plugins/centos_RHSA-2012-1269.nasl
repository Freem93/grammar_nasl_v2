#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1269 and 
# CentOS Errata and Security Advisory 2012:1269 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62217);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/29 00:03:02 $");

  script_cve_id("CVE-2012-2145");
  script_bugtraq_id(55608);
  script_osvdb_id(85704);
  script_xref(name:"RHSA", value:"2012:1269");

  script_name(english:"CentOS 6 : qpid (CESA-2012:1269)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qpid packages that fix one security issue, multiple bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Apache Qpid is a reliable, cross-platform, asynchronous messaging
system that supports the Advanced Message Queuing Protocol (AMQP) in
several common programming languages.

It was discovered that the Qpid daemon (qpidd) did not allow the
number of connections from clients to be restricted. A malicious
client could use this flaw to open an excessive amount of connections,
preventing other legitimate clients from establishing a connection to
qpidd. (CVE-2012-2145)

To address CVE-2012-2145, new qpidd configuration options were
introduced: max-negotiate-time defines the time during which initial
protocol negotiation must succeed, connection-limit-per-user and
connection-limit-per-ip can be used to limit the number of connections
per user and client host IP. Refer to the qpidd manual page for
additional details.

In addition, the qpid-cpp, qpid-qmf, qpid-tools, and python-qpid
packages have been upgraded to upstream version 0.14, which provides
support for Red Hat Enterprise MRG 2.2, as well as a number of bug
fixes and enhancements over the previous version. (BZ#840053,
BZ#840055, BZ#840056, BZ#840058)

All users of qpid are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97003b70"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qpid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-qmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-qpid-cpp-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"python-qpid-0.14-11.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-client-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-client-devel-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-client-devel-docs-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-client-rdma-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-client-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-cluster-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-devel-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-rdma-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-store-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-cpp-server-xml-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-qmf-devel-0.14-14.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qpid-tools-0.14-6.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rh-qpid-cpp-tests-0.14-22.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-qpid-qmf-0.14-14.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
