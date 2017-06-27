#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0747 and 
# CentOS Errata and Security Advisory 2013:0747 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65988);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/04 10:47:22 $");

  script_cve_id("CVE-2012-6537", "CVE-2012-6542", "CVE-2012-6546", "CVE-2012-6547", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-1826");
  script_bugtraq_id(57740, 57743, 58381, 58977, 58989, 58992, 58996);
  script_osvdb_id(89902, 89903, 90957, 90959, 90963, 90965, 90967);
  script_xref(name:"RHSA", value:"2013:0747");

  script_name(english:"CentOS 5 : kernel (CESA-2013:0747)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and three
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the Xen netback driver implementation in the
Linux kernel. A privileged guest user with access to a
para-virtualized network device could use this flaw to cause a long
loop in netback, leading to a denial of service that could potentially
affect the entire system. (CVE-2013-0216, Moderate)

* A flaw was found in the Xen PCI device back-end driver
implementation in the Linux kernel. A privileged guest user in a guest
that has a PCI passthrough device could use this flaw to cause a
denial of service that could potentially affect the entire system.
(CVE-2013-0231, Moderate)

* A NULL pointer dereference flaw was found in the IP packet
transformation framework (XFRM) implementation in the Linux kernel. A
local user who has the CAP_NET_ADMIN capability could use this flaw to
cause a denial of service. (CVE-2013-1826, Moderate)

* Information leak flaws were found in the XFRM implementation in the
Linux kernel. A local user who has the CAP_NET_ADMIN capability could
use these flaws to leak kernel stack memory to user-space.
(CVE-2012-6537, Low)

* An information leak flaw was found in the logical link control (LLC)
implementation in the Linux kernel. A local, unprivileged user could
use this flaw to leak kernel stack memory to user-space.
(CVE-2012-6542, Low)

* Two information leak flaws were found in the Linux kernel's
Asynchronous Transfer Mode (ATM) subsystem. A local, unprivileged user
could use these flaws to leak kernel stack memory to user-space.
(CVE-2012-6546, Low)

* An information leak flaw was found in the TUN/TAP device driver in
the Linux kernel's networking implementation. A local user with access
to a TUN/TAP virtual interface could use this flaw to leak kernel
stack memory to user-space. (CVE-2012-6547, Low)

Red Hat would like to thank the Xen project for reporting the
CVE-2013-0216 and CVE-2013-0231 issues.

This update also fixes the following bugs :

* The IPv4 code did not correctly update the Maximum Transfer Unit
(MTU) of the designed interface when receiving ICMP Fragmentation
Needed packets. Consequently, a remote host did not respond correctly
to ping attempts. With this update, the IPv4 code has been modified so
the MTU of the designed interface is adjusted as expected in this
situation. The ping command now provides the expected output.
(BZ#923353)

* Previously, the be2net code expected the last word of an MCC
completion message from the firmware to be transferred by direct
memory access (DMA) at once. However, this is not always true, and
could therefore cause the BUG_ON() macro to be triggered in the
be_mcc_compl_is_new() function, consequently leading to a kernel
panic. The BUG_ON() macro has been removed from be_mcc_compl_is_new(),
and the kernel panic no longer occurs in this scenario. (BZ#923910)

* Previously, the NFSv3 server incorrectly converted 64-bit cookies to
32-bit. Consequently, the cookies became invalid, which affected all
file system operations depending on these cookies, such as the READDIR
operation that is used to read entries from a directory. This led to
various problems, such as exported directories being empty or
displayed incorrectly, or an endless loop of the READDIRPLUS procedure
which could potentially cause a buffer overflow. This update modifies
knfsd code so that 64-bit cookies are now handled correctly and all
file system operations work as expected. (BZ#924087)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca60264a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-348.4.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-348.4.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
