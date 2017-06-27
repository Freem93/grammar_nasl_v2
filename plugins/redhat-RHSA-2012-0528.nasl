#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0528. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76642);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-3620");
  script_osvdb_id(81660);
  script_xref(name:"RHSA", value:"2012:0528");

  script_name(english:"RHEL 6 : MRG (RHSA-2012:0528)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Messaging packages that resolve one security issue, fix
multiple bugs, and add various enhancements are now available for Red
Hat Enterprise MRG 2.1 for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
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

It was found that Qpid accepted any password or SASL mechanism,
provided the remote user knew a valid cluster username. This could
give a remote attacker unauthorized access to the cluster, exposing
cluster messages and internal Qpid/MRG configurations. (CVE-2011-3620)

Note: If you are using an ACL, the cluster-username must be allowed to
publish to the qpid.cluster-credentials exchange. For example, if your
cluster-username is 'foo', in your ACL file :

acl allow foo@QPID publish exchange name=qpid.cluster-credentials

The CVE-2011-3620 fix changes the cluster initialization protocol. As
such, the cluster with all new version brokers must be restarted for
the changes to take effect. Refer below for details.

These updated packages provide numerous enhancements and bug fixes for
the Messaging component of MRG. Space precludes documenting all of
these changes in this advisory. Documentation for these changes will
be available shortly in the Technical Notes document linked to in the
References section.

All users of the Messaging capabilities of Red Hat Enterprise MRG 2.1
are advised to upgrade to these updated packages, which resolve the
issues and add the enhancements noted in the Red Hat Enterprise MRG 2
Technical Notes. After installing the updated packages, stop the
cluster by either running 'service qpidd stop' on all nodes, or
'qpid-cluster --all-stop' on any one of the cluster nodes. Once
stopped, restart the cluster with 'service qpidd start' on all nodes
for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3620.html"
  );
  # http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/2/html-single/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5155268e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0528.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-plumage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-example");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-jca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-jca-xarecovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
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
  rhsa = "RHSA-2012:0528";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-aviary-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-aviary-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-classads-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-classads-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-debuginfo-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-debuginfo-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-kbdd-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-kbdd-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-plumage-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-plumage-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-qmf-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-qmf-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-vm-gahp-7.6.5-0.14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-devel-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-devel-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-cpp-client-devel-docs-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-rdma-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-rdma-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-debuginfo-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-debuginfo-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-cluster-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-cluster-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-devel-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-devel-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-rdma-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-rdma-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-store-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-store-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-xml-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-xml-0.14-14.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-client-0.14-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-common-0.14-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-example-0.14-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-jca-0.14-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-jca-xarecovery-0.14-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-debuginfo-0.14-7.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-debuginfo-0.14-7.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-devel-0.14-7.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-devel-0.14-7.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-1.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-1.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-debuginfo-1.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-debuginfo-1.0-5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / condor-debuginfo / etc");
  }
}
