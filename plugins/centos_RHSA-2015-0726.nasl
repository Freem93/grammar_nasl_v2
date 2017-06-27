#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0726 and 
# CentOS Errata and Security Advisory 2015:0726 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82474);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-8159", "CVE-2015-1421");
  script_bugtraq_id(72356, 73060);
  script_osvdb_id(117716, 119630);
  script_xref(name:"RHSA", value:"2015:0726");

  script_name(english:"CentOS 7 : kernel (CESA-2015:0726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 7.

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

Red Hat would like to thank Mellanox for reporting the CVE-2014-8159
issue. The CVE-2015-1421 issue was discovered by Sun Baoliang of Red
Hat.

This update also fixes the following bugs :

* In certain systems with multiple CPUs, when a crash was triggered on
one CPU with an interrupt handler and this CPU sent Non-Maskable
Interrupt (NMI) to another CPU, and, at the same time, ioapic_lock had
already been acquired, a deadlock occurred in ioapic_lock. As a
consequence, the kdump service could become unresponsive. This bug has
been fixed and kdump now works as expected. (BZ#1197742)

* On Lenovo X1 Carbon 3rd Gen, X250, and T550 laptops, the
thinkpad_acpi module was not properly loaded, and thus the function
keys and radio switches did not work. This update applies a new string
pattern of BIOS version, which fixes this bug, and function keys and
radio switches now work as intended. (BZ#1197743)

* During a heavy file system load involving many worker threads, all
worker threads in the pool became blocked on a resource, and no
manager thread existed to create more workers. As a consequence, the
running processes became unresponsive. With this update, the logic
around manager creation has been changed to assure that the last
worker thread becomes a manager thread and does not start executing
work items. Now, a manager thread exists, spawns new workers as
needed, and processes no longer hang. (BZ#1197744)

* If a thin-pool's metadata enters read-only or fail mode, for
example, due to thin-pool running out of metadata or data space, any
attempt to make metadata changes such as creating a thin device or
snapshot thin device should error out cleanly. However, previously,
the kernel code returned verbose and alarming error messages to the
user. With this update, due to early trapping of attempt to make
metadata changes, informative errors are displayed, no longer
unnecessarily alarming the user. (BZ#1197745)

* When running Red Hat Enterprise Linux as a guest on Microsoft
Hyper-V hypervisor, the storvsc module did not return the correct
error code for the upper level Small Computer System Interface (SCSI)
subsystem. As a consequence, a SCSI command failed and storvsc did not
handle such a failure properly under some conditions, for example,
when RAID devices were created on top of storvsc devices. An upstream
patch has been applied to fix this bug, and storvsc now returns the
correct error code in the described situation. (BZ#1197749)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?085f0f7c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-229.1.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-229.1.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
