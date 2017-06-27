#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1173 and 
# CentOS Errata and Security Advisory 2013:1173 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69496);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/04 10:47:22 $");

  script_cve_id("CVE-2012-6544", "CVE-2013-2146", "CVE-2013-2206", "CVE-2013-2224", "CVE-2013-2232", "CVE-2013-2237");
  script_bugtraq_id(58990, 60324, 60715, 60858, 60893, 60953);
  script_osvdb_id(90964, 93906, 94456, 94706, 94793, 94853);
  script_xref(name:"RHSA", value:"2013:1173");

  script_name(english:"CentOS 6 : kernel (CESA-2013:1173)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the Linux kernel's Stream Control
Transmission Protocol (SCTP) implementation handled duplicate cookies.
If a local user queried SCTP connection information at the same time a
remote attacker has initialized a crafted SCTP connection to the
system, it could trigger a NULL pointer dereference, causing the
system to crash. (CVE-2013-2206, Important)

* It was found that the fix for CVE-2012-3552 released via
RHSA-2012:1304 introduced an invalid free flaw in the Linux kernel's
TCP/IP protocol suite implementation. A local, unprivileged user could
use this flaw to corrupt kernel memory via crafted sendmsg() calls,
allowing them to cause a denial of service or, potentially, escalate
their privileges on the system. (CVE-2013-2224, Important)

* A flaw was found in the Linux kernel's Performance Events
implementation. On systems with certain Intel processors, a local,
unprivileged user could use this flaw to cause a denial of service by
leveraging the perf subsystem to write into the reserved bits of the
OFFCORE_RSP_0 and OFFCORE_RSP_1 model-specific registers.
(CVE-2013-2146, Moderate)

* An invalid pointer dereference flaw was found in the Linux kernel's
TCP/IP protocol suite implementation. A local, unprivileged user could
use this flaw to crash the system or, potentially, escalate their
privileges on the system by using sendmsg() with an IPv6 socket
connected to an IPv4 destination. (CVE-2013-2232, Moderate)

* Information leak flaws in the Linux kernel's Bluetooth
implementation could allow a local, unprivileged user to leak kernel
memory to user-space. (CVE-2012-6544, Low)

* An information leak flaw in the Linux kernel could allow a
privileged, local user to leak kernel memory to user-space.
(CVE-2013-2237, Low)

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97775ec0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-358.18.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
