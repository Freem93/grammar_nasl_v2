#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1860. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78990);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:45 $");

  script_cve_id("CVE-2013-4299");
  script_bugtraq_id(63183);
  script_osvdb_id(98634);
  script_xref(name:"RHSA", value:"2013:1860");

  script_name(english:"RHEL 5 : kernel (RHSA-2013:1860)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.9 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* An information leak flaw was found in the way the Linux kernel's
device mapper subsystem, under certain conditions, interpreted data
written to snapshot block devices. An attacker could use this flaw to
read data from disk blocks in free space, which are normally
inaccessible. (CVE-2013-4299, Moderate)

Red Hat would like to thank Fujitsu for reporting this issue.

This update also fixes the following bugs :

* A previous fix to the kernel did not contain a memory barrier in the
percpu_up_write() function. Consequently, under certain circumstances,
a race condition could occur, leading to memory corruption and a
subsequent kernel panic. This update introduces a new memory barrier
pair, light_mb() and heavy_mb(), for per-CPU basis read and write
semaphores (percpu-rw-semaphores) ensuring that the race condition can
no longer occur. In addition, the read path performance of
'percpu-rw-semaphores' has been improved. (BZ#884735)

* Due to several related bugs in the be2net driver, the driver did not
handle firmware manipulation of the network cards using the Emulex
XE201 I/O controller properly. As a consequence, these NICs could not
recover from an error successfully. A series of patches has been
applied that fix the initialization sequence, and firmware download
and activation for the XE201 controller. Error recovery now works as
expected for the be2net NICs using the Emulex XE201 I/O controller.
(BZ#1019892)

* A bug in the be2net driver could cause packet corruption when
handling VLAN-tagged packets with no assigned VLAN group. This
happened because the be2net driver called a function responsible for
VLAN tag reinsertion in a wrong order in the code. The code has been
restructured and the be2net driver now calls the __vlan_put_tag()
function correctly, thus avoiding the packet corruption. (BZ#1019893)

* A previous patch to the kernel introduced the 'VLAN tag
re-insertion' workaround to resolve a problem with incorrectly handled
VLAN-tagged packets with no assigned VLAN group while the be2net
driver was in promiscuous mode. However, this solution led to packet
corruption and a subsequent kernel oops if such a processed packet was
a GRO packet. Therefore, a patch has been applied to restrict VLAN tag
re-insertion only to non-GRO packets. The be2net driver now processes
VLAN-tagged packets with no assigned VLAN group correctly in this
situation. (BZ#1023347)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1860.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^5\.9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1860";
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
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debug-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-debuginfo-common-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"kernel-doc-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"kernel-headers-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-headers-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-headers-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i686", reference:"kernel-xen-devel-2.6.18-348.21.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-348.21.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}
