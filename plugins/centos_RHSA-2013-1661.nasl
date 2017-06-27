#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1661 and 
# CentOS Errata and Security Advisory 2013:1661 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79172);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/26 13:44:50 $");

  script_cve_id("CVE-2012-4516", "CVE-2013-2561");
  script_bugtraq_id(55896, 58335);
  script_osvdb_id(86586, 90926);
  script_xref(name:"RHSA", value:"2013:1661");

  script_name(english:"CentOS 6 : ibutils / infinipath-psm / libibverbs / libmlx4 / librdmacm / mpitests / mstflint / etc (CESA-2013:1661)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10a5d528"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67426fa0"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000986.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b659647c"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a484774d"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b966b1a"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acacf898"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74230140"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f77e694"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2fdcf49"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f333d7c"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93e3b4cd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libibverbs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmlx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmlx4-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librdmacm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mpitests-mvapich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mpitests-mvapich-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mpitests-mvapich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mpitests-mvapich2-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mpitests-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mstflint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perftest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rdma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ibutils-1.5.7-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibutils-devel-1.5.7-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ibutils-libs-1.5.7-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-1.1.7-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-devel-1.1.7-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-devel-static-1.1.7-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libibverbs-utils-1.1.7-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libmlx4-1.0.5-4.el6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libmlx4-static-1.0.5-4.el6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-1.0.17-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-devel-1.0.17-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-static-1.0.17-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librdmacm-utils-1.0.17-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mpitests-mvapich-3.2-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mpitests-mvapich-psm-3.2-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mpitests-mvapich2-3.2-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mpitests-mvapich2-psm-3.2-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mpitests-openmpi-3.2-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mstflint-3.0-0.6.g6961daa.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openmpi-1.5.4-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openmpi-devel-1.5.4-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perftest-2.0-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"qperf-0.4.9-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rdma-3.10-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
