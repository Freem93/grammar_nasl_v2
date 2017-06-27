#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0674 and 
# Oracle Linux Security Advisory ELSA-2015-0674 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81766);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-7822", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8369");
  script_bugtraq_id(70749, 72061, 72347);
  script_osvdb_id(113728, 117131, 117810, 119630);
  script_xref(name:"RHSA", value:"2015:0674");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2015-0674)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0674 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

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

* A flaw was found in the way the Linux kernel's splice() system call
validated its parameters. On certain file systems, a local,
unprivileged user could use this flaw to write past the maximum file
size, and thus crash the system. (CVE-2014-7822, Moderate)

* A flaw was found in the way the Linux kernel's netfilter subsystem
handled generic protocol tracking. As demonstrated in the Stream
Control Transmission Protocol (SCTP) case, a remote attacker could use
this flaw to bypass intended iptables rule restrictions when the
associated connection tracking module was not loaded on the system.
(CVE-2014-8160, Moderate)

* It was found that the fix for CVE-2014-3601 was incomplete: the
Linux kernel's kvm_iommu_map_pages() function still handled IOMMU
mapping failures incorrectly. A privileged user in a guest with an
assigned host device could use this flaw to crash the host.
(CVE-2014-8369, Moderate)

Red Hat would like to thank Mellanox for reporting CVE-2014-8159, and
Akira Fujita of NEC for reporting CVE-2014-7822.

Bug fixes :

* The maximum amount of entries in the IPv6 route table
(net.ipv6.route.max_size) was 4096, and every route towards this
maximum size limit was counted. Communication to more systems was
impossible when the limit was exceeded. Now, only cached routes are
counted, which guarantees that the kernel does not run out of memory,
but the user can now install as many routes as the memory allows until
the kernel indicates it can no longer handle the amount of memory and
returns an error message.

In addition, the default 'net.ipv6.route.max_size' value has been
increased to 16384 for performance improvement reasons. (BZ#1177581)

* When the user attempted to scan for an FCOE-served Logical Unit
Number (LUN), after an initial LUN scan, a kernel panic occurred in
bnx2fc_init_task. System scanning for LUNs is now stable after LUNs
have been added. (BZ#1179098)

* Under certain conditions, such as when attempting to scan the
network for LUNs, a race condition in the bnx2fc driver could trigger
a kernel panic in bnx2fc_init_task. A patch fixing a locking issue
that caused the race condition has been applied, and scanning the
network for LUNs no longer leads to a kernel panic. (BZ#1179098)

* Previously, it was not possible to boot the kernel on Xen hypervisor
in PVHVM mode if more than 32 vCPUs were specified in the guest
configuration. Support for more than 32 vCPUs has been added, and the
kernel now boots successfully in the described situation. (BZ#1179343)

* When the NVMe driver allocated a namespace queue, it indicated that
it was a request-based driver when it was actually a block I/O-based
driver. Consequently, when NVMe driver was loaded along with a
request-based dm device, the system could terminate unexpectedly or
become unresponsive when attempting to access data. The NVMe driver no
longer sets the QUEUE_FLAG_STACKABLE bit when allocating a namespace
queue and device-mapper no longer perceives NVMe driver as
request-based; system hangs or crashes no longer occur. (BZ#1180555)

* If a user attempted to apply an NVRAM firmware update when running
the tg3 module provided with Red Hat Enterprise Linux 6.6 kernels, the
update could fail. As a consequence, the Network Interface Card (NIC)
could stay in an unusable state and this could prevent the entire
system from booting. The tg3 module has been updated to correctly
apply firmware updates. (BZ#1182903)

* Support for key sizes of 256 and 192 bits has been added to AES-NI.
(BZ#1184332)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004878.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-504.12.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-504.12.2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-504.12.2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-504.12.2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
