#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0051 and 
# CentOS Errata and Security Advisory 2012:0051 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57668);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2011-4622", "CVE-2012-0029");
  script_bugtraq_id(51172);
  script_osvdb_id(77985);
  script_xref(name:"RHSA", value:"2012:0051");

  script_name(english:"CentOS 5 : kvm (CESA-2012:0051)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

A heap overflow flaw was found in the way QEMU-KVM emulated the e1000
network interface card. A privileged guest user in a virtual machine
whose network interface is configured to use the e1000 emulated driver
could use this flaw to crash the host or, possibly, escalate their
privileges on the host. (CVE-2012-0029)

A flaw was found in the way the KVM subsystem of a Linux kernel
handled PIT (Programmable Interval Timer) IRQs (interrupt requests)
when there was no virtual interrupt controller set up. A malicious
user in the kvm group on the host could force this situation to occur,
resulting in the host crashing. (CVE-2011-4622)

Red Hat would like to thank Nicolae Mogoreanu for reporting
CVE-2012-0029.

All KVM users should upgrade to these updated packages, which contain
backported patches to correct these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d22d35c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-239.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-debug-83-239.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-239.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-239.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-239.el5.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
