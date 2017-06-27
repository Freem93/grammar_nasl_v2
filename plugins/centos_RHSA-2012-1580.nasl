#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1580 and 
# CentOS Errata and Security Advisory 2012:1580 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63305);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2009-4307", "CVE-2011-4131", "CVE-2012-2100", "CVE-2012-2375", "CVE-2012-4444", "CVE-2012-4565", "CVE-2012-5517");
  script_bugtraq_id(53414, 53615, 56346, 56527, 56891);
  script_osvdb_id(77100, 81711, 88048, 88364, 88504);
  script_xref(name:"RHSA", value:"2012:1580");

  script_name(english:"CentOS 6 : kernel (CESA-2012:1580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, numerous
bugs and add one enhancement are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* It was found that the RHSA-2012:0862 update did not correctly fix
the CVE-2011-4131 issue. A malicious Network File System version 4
(NFSv4) server could return a crafted reply to a GETACL request,
causing a denial of service on the client. (CVE-2012-2375, Moderate)

* A divide-by-zero flaw was found in the TCP Illinois congestion
control algorithm implementation in the Linux kernel. If the TCP
Illinois congestion control algorithm were in use (the sysctl
net.ipv4.tcp_congestion_control variable set to 'illinois'), a local,
unprivileged user could trigger this flaw and cause a denial of
service. (CVE-2012-4565, Moderate)

* A NULL pointer dereference flaw was found in the way a new node's
hot added memory was propagated to other nodes' zonelists. By
utilizing this newly added memory from one of the remaining nodes, a
local, unprivileged user could use this flaw to cause a denial of
service. (CVE-2012-5517, Moderate)

* It was found that the initial release of Red Hat Enterprise Linux 6
did not correctly fix the CVE-2009-4307 issue, a divide-by-zero flaw
in the ext4 file system code. A local, unprivileged user with the
ability to mount an ext4 file system could use this flaw to cause a
denial of service. (CVE-2012-2100, Low)

* A flaw was found in the way the Linux kernel's IPv6 implementation
handled overlapping, fragmented IPv6 packets. A remote attacker could
potentially use this flaw to bypass protection mechanisms (such as a
firewall or intrusion detection system (IDS)) when sending network
packets to a target system. (CVE-2012-4444, Low)

Red Hat would like to thank Antonios Atlasis working with Beyond
Security's SecuriTeam Secure Disclosure program and Loganaden
Velvindron of AFRINIC for reporting CVE-2012-4444. The CVE-2012-2375
issue was discovered by Jian Li of Red Hat, and CVE-2012-4565 was
discovered by Rodrigo Freire of Red Hat.

This update also fixes numerous bugs and adds one enhancement. Space
precludes documenting all of these changes in this advisory.
Documentation for these changes will be available shortly from the Red
Hat Enterprise Linux 6.3 Technical Notes document linked to in the
References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, fix these bugs and add the
enhancement noted in the Technical Notes. The system must be rebooted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-December/019039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31eefacb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-279.19.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
