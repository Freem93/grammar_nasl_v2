#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1714 and 
# CentOS Errata and Security Advisory 2015:1714 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86507);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/22 14:23:03 $");

  script_cve_id("CVE-2015-3247");
  script_osvdb_id(127120);
  script_xref(name:"RHSA", value:"2015:1714");

  script_name(english:"CentOS 7 : spice (CESA-2015:1714)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spice package that fixes one security issue is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol for virtual environments. SPICE users can
access a virtualized desktop or server from the local system or any
system with network access to the server. SPICE is used in Red Hat
Enterprise Linux for viewing virtualized guests running on the
Kernel-based Virtual Machine (KVM) hypervisor or on Red Hat Enterprise
Virtualization Hypervisors.

A race condition flaw, leading to a heap-based memory corruption, was
found in spice's worker_update_monitors_config() function, which runs
under the QEMU-KVM context on the host. A user in a guest could
leverage this flaw to crash the host QEMU-KVM process or, possibly,
execute arbitrary code with the privileges of the host QEMU-KVM
process. (CVE-2015-3247)

This issue was discovered by Frediano Ziglio of Red Hat.

All spice users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb63aec3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-server-0.12.4-9.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"spice-server-devel-0.12.4-9.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
