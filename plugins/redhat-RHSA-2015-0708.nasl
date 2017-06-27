#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0708. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82492);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2015-0203", "CVE-2015-0223", "CVE-2015-0224");
  script_xref(name:"RHSA", value:"2015:0708");

  script_name(english:"RHEL 7 : MRG (RHSA-2015:0708)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qpid packages that fix multiple security issues and one bug
are now available for Red Hat Enterprise MRG 3 for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise MRG is a next-generation IT infrastructure
incorporating Messaging, Real Time, and Grid functionality. It offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

MRG Messaging is a high-speed reliable messaging distribution for
Linux based on AMQP (Advanced Message Queuing Protocol), an open
protocol standard for enterprise messaging that is designed to make
mission critical messaging widely available as a standard service, and
to make enterprise messaging interoperable across platforms,
programming languages, and vendors.

MRG Messaging includes AMQP messaging broker; AMQP client libraries
for C++, Java JMS, and Python; as well as persistence libraries and
management tools.

It was discovered that the Qpid daemon (qpidd) did not restrict access
to anonymous users when the ANONYMOUS mechanism was disallowed.
(CVE-2015-0223)

A flaw was found in the way the Qpid daemon (qpidd) processed certain
protocol sequences. An unauthenticated attacker able to send a
specially crafted protocol sequence set that could use this flaw to
crash qpidd. (CVE-2015-0203, CVE-2015-0224)

Red Hat would like to thank the Apache Software Foundation for
reporting the CVE-2015-0203 issue. Upstream acknowledges G. Geshev
from MWR Labs as the original reporter.

This update also fixes the following bugs :

* Previously, the neutron messaging client rewrote (by method of
'monkey-patching') the python selector module to support eventlet
threading. The rewritten client did not update select.poll() during
this process, which is used by qpid-python to manage I/O. This
resulted in poll() deadlocks and neutron server hangs. The fix
introduces updates to the python-qpid library that avoid calling
poll() if eventlet threading is detected. Instead, the eventlet-aware
select() is called, which prevents deadlocks from occurring and
corrects the originally reported issue. (BZ#1175872)

* It was discovered that the QPID Broker aborted with an uncaught
UnknownExchangeTypeException when the client attempted to request an
unsupported exchange type. The code for the Exchange Registry and Node
Policy has been improved to prevent this issue from happening again.
(BZ#1186694)

Users of the Messaging capabilities of Red Hat Enterprise MRG 3, which
is layered on Red Hat Enterprise Linux 7, are advised to upgrade to
these updated packages, which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0708.html"
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
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdb-cxx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdb-cxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-linearstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0708";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libdb-cxx-5.3.21-17.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libdb-cxx-devel-5.3.21-17.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libdb-debuginfo-5.3.21-17.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-qpid-0.22-19.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-qmf-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qpid-cpp-client-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-client-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-client-devel-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"qpid-cpp-client-devel-docs-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-client-rdma-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qpid-cpp-debuginfo-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-debuginfo-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qpid-cpp-server-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-devel-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-ha-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-linearstore-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-cpp-server-rdma-0.22-51.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qpid-qmf-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-qmf-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qpid-qmf-debuginfo-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-qmf-debuginfo-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-qmf-devel-0.22-41.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-qpid-qmf-0.22-41.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libdb-cxx / libdb-cxx-devel / libdb-debuginfo / python-qpid / etc");
  }
}
