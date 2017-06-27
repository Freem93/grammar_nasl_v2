#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0782. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82636);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2013-2596", "CVE-2014-3690", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-8159", "CVE-2014-8884", "CVE-2015-1421");
  script_osvdb_id(92267, 110564, 110565, 113629, 114957, 117716, 119630);
  script_xref(name:"RHSA", value:"2015:0782");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:0782)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.5 Extended
Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the Linux kernel's Infiniband subsystem did not
properly sanitize input parameters while registering memory regions
from user space via the (u)verbs API. A local user with access to a
/dev/infiniband/uverbsX device could use this flaw to crash the system
or, potentially, escalate their privileges on the system.
(CVE-2014-8159, Important)

* A use-after-free flaw was found in the way the Linux kernel's SCTP
implementation handled authentication key reference counting during
INIT collisions. A remote attacker could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2015-1421, Important)

* An integer overflow flaw was found in the way the Linux kernel's
Frame Buffer device implementation mapped kernel memory to user space
via the mmap syscall. A local user able to access a frame buffer
device file (/dev/fb*) could possibly use this flaw to escalate their
privileges on the system. (CVE-2013-2596, Important)

* It was found that the Linux kernel's KVM implementation did not
ensure that the host CR4 control register value remained unchanged
across VM entries on the same virtual CPU. A local, unprivileged user
could use this flaw to cause a denial of service on the system.
(CVE-2014-3690, Moderate)

* It was found that the parse_rock_ridge_inode_internal() function of
the Linux kernel's ISOFS implementation did not correctly check
relocated directories when processing Rock Ridge child link (CL) tags.
An attacker with physical access to the system could use a specially
crafted ISO image to crash the system or, potentially, escalate their
privileges on the system. (CVE-2014-5471, CVE-2014-5472, Low)

* A stack-based buffer overflow flaw was found in the
TechnoTrend/Hauppauge DEC USB device driver. A local user with write
access to the corresponding device could use this flaw to crash the
kernel or, potentially, elevate their privileges on the system.
(CVE-2014-8884, Low)

Red Hat would like to thank Mellanox for reporting CVE-2014-8159, and
Andy Lutomirski for reporting CVE-2014-3690. The CVE-2015-1421 issue
was discovered by Sun Baoliang of Red Hat.

This update also fixes the following bugs :

* Previously, a NULL pointer check that is needed to prevent an oops
in the nfs_async_inode_return_delegation() function was removed. As a
consequence, a NFS4 client could terminate unexpectedly. The missing
NULL pointer check has been added back, and NFS4 client no longer
crashes in this situation. (BZ#1187638)

* Due to unbalanced multicast join and leave processing, the attempt
to leave a multicast group that had not previously completed a join
became unresponsive. This update resolves multiple locking issues in
the IPoIB multicast code that allowed multicast groups to be left
before the joining was entirely completed. Now, multicast join and
leave failures or lockups no longer occur in the described situation.
(BZ#1187663)

* A failure to leave a multicast group which had previously been
joined prevented the attempt to unregister from the 'sa' service.
Multiple locking issues in the IPoIB multicast join and leave
processing have been fixed so that leaving a group that has completed
its join process is successful. As a result, attempts to unregister
from the 'sa' service no longer lock up due to leaked resources.
(BZ#1187665)

* Due to a regression, when large reads which partially extended
beyond the end of the underlying device were done, the raw driver
returned the EIO error code instead of returning a short read covering
the valid part of the device. The underlying source code has been
patched, and the raw driver now returns a short read for the remainder
of the device. (BZ#1195746)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8884.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0782.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
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
if (! ereg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0782";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-abi-whitelists-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-doc-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-firmware-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-headers-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-headers-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-headers-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-431.53.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-431.53.2.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
