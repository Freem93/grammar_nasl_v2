#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1661. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71015);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-4516", "CVE-2013-2561");
  script_bugtraq_id(55896, 58335);
  script_osvdb_id(86586, 90926);
  script_xref(name:"RHSA", value:"2013:1661");

  script_name(english:"RHEL 6 : RDMA stack (RHSA-2013:1661)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rdma, libibverbs, libmlx4, librdmacm, qperf, perftest,
openmpi, compat-openmpi, infinipath-psm, mpitests, and rds-tools
packages that fix two security issues, several bugs, and add various
enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Enterprise Linux includes a collection of Infiniband and iWARP
utilities, libraries and development packages for writing applications
that use Remote Direct Memory Access (RDMA) technology.

A flaw was found in the way ibutils handled temporary files. A local
attacker could use this flaw to cause arbitrary files to be
overwritten as the root user via a symbolic link attack.
(CVE-2013-2561)

It was discovered that librdmacm used a static port to connect to the
ib_acm service. A local attacker able to run a specially crafted
ib_acm service on that port could use this flaw to provide incorrect
address resolution information to librmdacm applications.
(CVE-2012-4516)

The CVE-2012-4516 issue was discovered by Florian Weimer of the Red
Hat Product Security Team.

This advisory updates the following packages to the latest upstream
releases, providing a number of bug fixes and enhancements over the
previous versions :

* libibverbs-1.1.7 * libmlx4-1.0.5 * librdmacm-1.0.17 * mstflint-3.0 *
perftest-2.0 * qperf-0.4.9 * rdma-3.10

Several bugs have been fixed in the openmpi, mpitests, ibutils, and
infinipath-psm packages.

The most notable changes in these updated packages from the RDMA stack
are the following :

* Multiple bugs in the Message Passing Interface (MPI) test packages
were resolved, allowing more of the mpitest applications to pass on
the underlying MPI implementations.

* The libmlx4 package now includes dracut module files to ensure that
any necessary custom configuration of mlx4 port types is included in
the initramfs dracut builds.

* Multiple test programs in the perftest and qperf packages now work
properly over RoCE interfaces, or when specifying the use of rdmacm
queue pairs.

* The mstflint package has been updated to the latest upstream
version, which is now capable of burning firmware on newly released
Mellanox Connect-IB hardware.

* A compatibility problem between the openmpi and infinipath-psm
packages has been resolved with new builds of these packages.

All RDMA users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1661.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibverbs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmlx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librdmacm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-mvapich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-mvapich-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-mvapich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-mvapich2-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mpitests-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mstflint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mstflint-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openmpi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perftest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perftest-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qperf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rdma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1661";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-debuginfo-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-debuginfo-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-devel-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-devel-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-libs-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-libs-1.5.7-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-debuginfo-3.0.1-115.1015_open.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-debuginfo-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-debuginfo-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-devel-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-devel-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-devel-static-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-devel-static-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-utils-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-utils-1.1.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-debuginfo-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-debuginfo-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-static-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-static-1.0.5-4.el6.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-debuginfo-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-debuginfo-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-devel-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-devel-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-static-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-static-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-utils-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-utils-1.0.17-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mpitests-debuginfo-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-debuginfo-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mpitests-mvapich-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-mvapich-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-mvapich-psm-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mpitests-mvapich2-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-mvapich2-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-mvapich2-psm-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mpitests-openmpi-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mpitests-openmpi-3.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mstflint-3.0-0.6.g6961daa.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mstflint-3.0-0.6.g6961daa.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mstflint-debuginfo-3.0-0.6.g6961daa.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mstflint-debuginfo-3.0-0.6.g6961daa.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openmpi-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openmpi-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openmpi-debuginfo-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openmpi-debuginfo-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openmpi-devel-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openmpi-devel-1.5.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perftest-2.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perftest-2.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perftest-debuginfo-2.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perftest-debuginfo-2.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qperf-0.4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qperf-0.4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qperf-debuginfo-0.4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qperf-debuginfo-0.4.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rdma-3.10-3.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibutils / ibutils-debuginfo / ibutils-devel / ibutils-libs / etc");
  }
}
