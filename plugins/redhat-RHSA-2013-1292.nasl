#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1292. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70163);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-3511", "CVE-2013-2141", "CVE-2013-4162");
  script_bugtraq_id(55151, 60254, 61411);
  script_osvdb_id(84904, 93907, 95614);
  script_xref(name:"RHSA", value:"2013:1292");

  script_name(english:"RHEL 5 : kernel (RHSA-2013:1292)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A use-after-free flaw was found in the madvise() system call
implementation in the Linux kernel. A local, unprivileged user could
use this flaw to cause a denial of service or, potentially, escalate
their privileges. (CVE-2012-3511, Moderate)

* A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled IPv6 sockets that used the UDP_CORK option. A
local, unprivileged user could use this flaw to cause a denial of
service. (CVE-2013-4162, Moderate)

* An information leak flaw in the Linux kernel could allow a local,
unprivileged user to leak kernel memory to user-space. (CVE-2013-2141,
Low)

Red Hat would like to thank Hannes Frederic Sowa for reporting
CVE-2013-4162.

This update also fixes the following bugs :

* A bug in the be2net driver prevented communication between NICs
using be2net. This update applies a patch addressing this problem
along with several other upstream patches that fix various other
problems. Traffic between NICs using the be2net driver now proceeds as
expected. (BZ#983864)

* A recent patch fixing a problem that prevented communication between
NICs using the be2net driver caused the firmware of NICs to become
unresponsive, and thus triggered a kernel panic. The problem was
caused by unnecessary usage of a hardware workaround that allows
skipping VLAN tag insertion. A patch has been applied and the
workaround is now used only when the multi-channel configuration is
enabled on the NIC. Note that the bug only affected the NICs with
firmware version 4.2.xxxx. (BZ#999819)

* A bug in the autofs4 mount expiration code could cause the autofs4
module to falsely report a busy tree of NFS mounts as 'not in use'.
Consequently, automount attempted to unmount the tree and failed with
a 'failed to umount offset' error, leaving the mount tree to appear as
empty directories. A patch has been applied to remove an incorrectly
used autofs dentry mount check and the aforementioned problem no
longer occurs. (BZ#1001488)

* A race condition in the be_open function in the be2net driver could
trigger the BUG_ON() macro, which resulted in a kernel panic. A patch
addressing this problem has been applied and the race condition is now
avoided by enabling polling before enabling interrupts globally. The
kernel no longer panics in this situation. (BZ#1005239)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1292.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1292";
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
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debuginfo-common-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-348.18.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-348.18.1.el5")) flag++;


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
