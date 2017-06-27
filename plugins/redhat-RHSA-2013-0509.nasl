#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0509. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64759);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_bugtraq_id(55890);
  script_xref(name:"RHSA", value:"2013:0509");

  script_name(english:"RHEL 6 : rdma (RHSA-2013:0509)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated RDMA packages that fix multiple security issues, various bugs,
and add an enhancement are now available for Red Hat Enterprise Linux
6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise Linux includes a collection of InfiniBand and iWARP
utilities, libraries and development packages for writing applications
that use Remote Direct Memory Access (RDMA) technology.

A denial of service flaw was found in the way ibacm managed reference
counts for multicast connections. An attacker could send specially
crafted multicast packets that would cause the ibacm daemon to crash.
(CVE-2012-4517)

It was found that the ibacm daemon created some files with
world-writable permissions. A local attacker could use this flaw to
overwrite the contents of the ibacm.log or ibacm.port file, allowing
them to mask certain actions from the log or cause ibacm to run on a
non-default port. (CVE-2012-4518)

CVE-2012-4518 was discovered by Florian Weimer of the Red Hat Product
Security Team and Kurt Seifried of the Red Hat Security Response Team.

The InfiniBand/iWARP/RDMA stack components have been upgraded to more
recent upstream versions.

This update also fixes the following bugs :

* Previously, the 'ibnodes -h' command did not show a proper usage
message. With this update the problem is fixed and 'ibnodes -h' now
shows the correct usage message. (BZ#818606)

* Previously, the ibv_devinfo utility erroneously showed iWARP cxgb3
hardware's physical state as invalid even when the device was working.
For iWARP hardware, the phys_state field has no meaning. This update
patches the utility to not print out anything for this field when the
hardware is iWARP hardware. (BZ#822781)

* Prior to the release of Red Hat Enterprise Linux 6.3, the kernel
created the InfiniBand device files in the wrong place and a udev
rules file was used to force the devices to be created in the proper
place. With the update to 6.3, the kernel was fixed to create the
InfiniBand device files in the proper place, and so the udev rules
file was removed as no longer being necessary. However, a bug in the
kernel device creation meant that, although the devices were now being
created in the right place, they had incorrect permissions.
Consequently, when users attempted to run an RDMA application as a
non-root user, the application failed to get the necessary permissions
to use the RDMA device and the application terminated. This update
puts a new udev rules file in place. It no longer attempts to create
the InfiniBand devices since they already exist, but it does correct
the device permissions on the files. (BZ#834428)

* Previously, using the 'perfquery -C' command with a host name caused
the perfquery utility to become unresponsive. The list of controllers
to process was never cleared and the process looped infinitely on a
single controller. A patch has been applied to make sure that in the
case where the user passes in the -C option, the controller list is
cleared out once that controller has been processed. As a result,
perfquery now works as expected in the scenario described. (BZ#847129)

* The OpenSM init script did not handle the case where there were no
configuration files under '/etc/rdma/opensm.conf.*'. With this update,
the script as been patched and the InfiniBand Subnet Manager, OpenSM,
now starts as expected in the scenario described. (BZ#862857)

This update also adds the following enhancement :

* This update provides an updated mlx4_ib Mellanox driver which
includes Single Root I/O Virtualization (SR-IOV) support. (BZ#869737)

All users of RDMA are advised to upgrade to these updated packages,
which fix these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0509.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibacm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibacm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibacm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibsim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibsim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ibutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infiniband-diags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infiniband-diags-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infiniband-diags-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infiniband-diags-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinipath-psm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibmad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibmad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibmad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibmad-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibumad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibumad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibumad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libibumad-static");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rdma");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
  rhsa = "RHSA-2013:0509";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibacm-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibacm-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibacm-debuginfo-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibacm-debuginfo-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibacm-devel-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibacm-devel-1.0.8-0.git7a3adb7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibsim-0.5-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibsim-0.5-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibsim-debuginfo-0.5-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibsim-debuginfo-0.5-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-debuginfo-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-debuginfo-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-devel-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-devel-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ibutils-libs-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ibutils-libs-1.5.7-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"infiniband-diags-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infiniband-diags-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"infiniband-diags-debuginfo-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infiniband-diags-debuginfo-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"infiniband-diags-devel-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infiniband-diags-devel-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"infiniband-diags-devel-static-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infiniband-diags-devel-static-1.5.12-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-3.0.1-115.1015_open.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-debuginfo-3.0.1-115.1015_open.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"infinipath-psm-devel-3.0.1-115.1015_open.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibmad-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibmad-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibmad-debuginfo-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibmad-debuginfo-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibmad-devel-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibmad-devel-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibmad-static-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibmad-static-1.3.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibumad-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibumad-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibumad-debuginfo-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibumad-debuginfo-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibumad-devel-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibumad-devel-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibumad-static-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibumad-static-1.3.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-debuginfo-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-debuginfo-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-devel-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-devel-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-devel-static-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-devel-static-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libibverbs-utils-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libibverbs-utils-1.1.6-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-debuginfo-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-debuginfo-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libmlx4-static-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libmlx4-static-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-debuginfo-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-debuginfo-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-devel-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-devel-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-static-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-static-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"librdmacm-utils-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"librdmacm-utils-1.0.17-0.git4b5c1aa.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"opensm-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"opensm-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"opensm-debuginfo-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"opensm-debuginfo-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"opensm-devel-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"opensm-devel-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"opensm-libs-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"opensm-libs-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"opensm-static-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"opensm-static-3.3.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rdma-3.6-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibacm / ibacm-debuginfo / ibacm-devel / ibsim / ibsim-debuginfo / etc");
  }
}
