#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1221 and 
# CentOS Errata and Security Advisory 2015:1221 respectively.
#

include("compat.inc");

if (description)
{
  script_id(84769);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2011-5321", "CVE-2015-1593", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3636");
  script_osvdb_id(118498, 119797, 120282, 120284, 121578);
  script_xref(name:"RHSA", value:"2015:1221");

  script_name(english:"CentOS 6 : kernel (CESA-2015:1221)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A NULL pointer dereference flaw was found in the way the Linux
kernel's virtual console implementation handled reference counting
when accessing pseudo-terminal device files (/dev/pts/*). A local,
unprivileged attacker could use this flaw to crash the system.
(CVE-2011-5321, Moderate)

* It was found that the Linux kernel's ping socket implementation did
not properly handle socket unhashing during spurious disconnects,
which could lead to a use-after-free flaw. On x86-64 architecture
systems, a local user able to create ping sockets could use this flaw
to crash the system. On non-x86-64 architecture systems, a local user
able to create ping sockets could use this flaw to escalate their
privileges on the system. (CVE-2015-3636, Moderate)

* An integer overflow flaw was found in the way the Linux kernel
randomized the stack for processes on certain 64-bit architecture
systems, such as x86-64, causing the stack entropy to be reduced by
four. (CVE-2015-1593, Low)

* A flaw was found in the way the Linux kernel's 32-bit emulation
implementation handled forking or closing of a task with an 'int80'
entry. A local user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-2830, Low)

* It was found that the Linux kernel's TCP/IP protocol suite
implementation for IPv6 allowed the Hop Limit value to be set to a
smaller value than the default one. An attacker on a local network
could use this flaw to prevent systems on that network from sending or
receiving network packets. (CVE-2015-2922, Low)

These updated kernel packages also include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes,
users are directed to the following article on the Red Hat Customer
Portal :

https://access.redhat.com/articles/1506133

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-July/021242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6449aa7b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-504.30.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-504.30.3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
