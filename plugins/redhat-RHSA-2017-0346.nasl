#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0346. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97464);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2017-2634", "CVE-2017-6074");
  script_osvdb_id(152302, 152502);
  script_xref(name:"RHSA", value:"2017:0346");

  script_name(english:"RHEL 5 : kernel (RHSA-2017:0346)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 5.9
Long Life.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A use-after-free flaw was found in the way the Linux kernel's
Datagram Congestion Control Protocol (DCCP) implementation freed SKB
(socket buffer) resources for a DCCP_PKT_REQUEST packet when the
IPV6_RECVPKTINFO option is set on the socket. A local, unprivileged
user could use this flaw to alter the kernel memory, allowing them to
escalate their privileges on the system. (CVE-2017-6074, Important)

* It was found that the Linux kernel's Datagram Congestion Control
Protocol (DCCP) implementation used the IPv4-only
inet_sk_rebuild_header() function for both IPv4 and IPv6 DCCP
connections, which could result in memory corruptions. A remote
attacker could use this flaw to crash the system. (CVE-2017-2634,
Moderate)

Important: This update disables the DCCP kernel module at load time by
using the kernel module blacklist method. The module is disabled in an
attempt to reduce further exposure to additional issues. (BZ#1426309)

Red Hat would like to thank Andrey Konovalov (Google) for reporting
CVE-2017-6074. The CVE-2017-2634 issue was discovered by Wade Mealing
(Red Hat Product Security)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-2634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-6074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/2706661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0346.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5\.9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0346";
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
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"kernel-doc-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"kernel-headers-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-headers-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-devel-2.6.18-348.33.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-348.33.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}
