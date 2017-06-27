#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1304 and 
# CentOS Errata and Security Advisory 2012:1304 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62316);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/08 10:48:35 $");

  script_cve_id("CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552");
  script_bugtraq_id(53668, 53965, 53971, 54702, 55359);
  script_osvdb_id(82808, 83073, 83185, 85606, 85723);
  script_xref(name:"RHSA", value:"2012:1304");

  script_name(english:"CentOS 6 : kernel (CESA-2012:1304)");
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
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* An integer overflow flaw was found in the i915_gem_do_execbuffer()
function in the Intel i915 driver in the Linux kernel. A local,
unprivileged user could use this flaw to cause a denial of service.
This issue only affected 32-bit systems. (CVE-2012-2384, Moderate)

* A memory leak flaw was found in the way the Linux kernel's memory
subsystem handled resource clean up in the mmap() failure path when
the MAP_HUGETLB flag was set. A local, unprivileged user could use
this flaw to cause a denial of service. (CVE-2012-2390, Moderate)

* A race condition was found in the way access to inet->opt ip_options
was synchronized in the Linux kernel's TCP/IP protocol suite
implementation. Depending on the network facing applications running
on the system, a remote attacker could possibly trigger this flaw to
cause a denial of service. A local, unprivileged user could use this
flaw to cause a denial of service regardless of the applications the
system runs. (CVE-2012-3552, Moderate)

* A flaw was found in the way the Linux kernel's dl2k driver, used by
certain D-Link Gigabit Ethernet adapters, restricted IOCTLs. A local,
unprivileged user could use this flaw to issue potentially harmful
IOCTLs, which could cause Ethernet adapters using the dl2k driver to
malfunction (for example, losing network connectivity).
(CVE-2012-2313, Low)

* A flaw was found in the way the msg_namelen variable in the
rds_recvmsg() function of the Linux kernel's Reliable Datagram Sockets
(RDS) protocol implementation was initialized. A local, unprivileged
user could use this flaw to leak kernel stack memory to user-space.
(CVE-2012-3430, Low)

Red Hat would like to thank Hafid Lin for reporting CVE-2012-3552, and
Stephan Mueller for reporting CVE-2012-2313. The CVE-2012-3430 issue
was discovered by the Red Hat InfiniBand team.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?531a2cbb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-279.9.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
