#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2552 and 
# CentOS Errata and Security Advisory 2015:2552 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87281);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104");
  script_osvdb_id(130089, 130090);
  script_xref(name:"RHSA", value:"2015:2552");

  script_name(english:"CentOS 7 : kernel (CESA-2015:2552)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the x86 ISA (Instruction Set Architecture) is
prone to a denial of service attack inside a virtualized environment
in the form of an infinite loop in the microcode due to the way
(sequential) delivering of benign exceptions such as #AC (alignment
check exception) and #DB (debug exception) is handled. A privileged
user inside a guest could use these flaws to create denial of service
conditions on the host kernel. (CVE-2015-5307, CVE-2015-8104,
Important)

Red Hat would like to thank Ben Serebrin of Google Inc. for reporting
the CVE-2015-5307 issue.

This update also fixes the following bugs :

* On Intel Xeon v5 platforms, the processor frequency was always tied
to the highest possible frequency. Switching p-states on these client
platforms failed. This update sets the idle frequency, busy frequency,
and processor frequency values by determining the range and adjusting
the minimal and maximal percent limit values. Now, switching p-states
on the aforementioned client platforms proceeds successfully.
(BZ#1273926)

* Due to a validation error of in-kernel memory-mapped I/O (MMIO)
tracing, a VM became previously unresponsive when connected to Red Hat
Enterprise Virtualization Hypervisor. The provided patch fixes this
bug by dropping the check in MMIO handler, and a VM continues running
as expected. (BZ#1275150)

* Due to retry-able command errors, the NVMe driver previously leaked
I/O descriptors and DMA mappings. As a consequence, the kernel could
become unresponsive during the hot-unplug operation if a driver was
removed. This update fixes the driver memory leak bug on command
retries, and the kernel no longer hangs in this situation.
(BZ#1279792)

* The hybrid_dma_data() function was not initialized before use, which
caused an invalid memory access when hot-plugging a PCI card. As a
consequence, a kernel oops occurred. The provided patch makes sure
hybrid_dma_data() is initialized before use, and the kernel oops no
longer occurs in this situation. (BZ#1279793)

* When running PowerPC (PPC) KVM guests and the host was experiencing
a lot of page faults, for example because it was running low on
memory, the host sometimes triggered an incorrect kind of interrupt in
the guest: a data storage exception instead of a data segment
exception. This caused a kernel panic of the PPC KVM guest. With this
update, the host kernel synthesizes a segment fault if the
corresponding Segment Lookaside Buffer (SLB) lookup fails, which
prevents the kernel panic from occurring. (BZ#1281423)

* The kernel accessed an incorrect area of the khugepaged process
causing Logical Partitioning (LPAR) to become unresponsive, and an
oops occurred in medlp5. The backported upstream patch prevents an
LPAR hang, and the oops no longer occurs. (BZ#1281424)

* When the sctp module was loaded and a route to an association
endpoint was removed after receiving an Out-of-The-Blue (OOTB) chunk
but before incrementing the 'dropped because of missing route' SNMP
statistic, a NULL pointer Dereference kernel panic previously
occurred. This update fixes the race condition between OOTB response
and route removal. (BZ#1281426)

* The cpuscaling test of the certification test suite previously
failed due to a rounding bug in the intel-pstate driver. This bug has
been fixed and the cpuscaling test now passes. (BZ#1281491)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-December/002732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5631488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-327.3.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-327.3.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
