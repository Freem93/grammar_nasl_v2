#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1087 and 
# CentOS Errata and Security Advisory 2015:1087 respectively.
#

include("compat.inc");

if (description)
{
  script_id(84092);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2015-3209");
  script_bugtraq_id(75123);
  script_osvdb_id(123147);
  script_xref(name:"RHSA", value:"2015:1087");

  script_name(english:"CentOS 6 : qemu-kvm (CESA-2015:1087)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

A flaw was found in the way QEMU's AMD PCnet Ethernet emulation
handled multi-TMD packets with a length above 4096 bytes. A privileged
guest user in a guest with an AMD PCNet ethernet card enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the hosting QEMU process. (CVE-2015-3209)

Red Hat would like to thank Matt Tait of Google's Project Zero
security team for reporting this issue.

All qemu-kvm users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021168.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1df5bf72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/11");
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
if (rpm_check(release:"CentOS-6", reference:"qemu-guest-agent-0.12.1.2-2.448.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.448.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.448.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.448.el6_6.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
