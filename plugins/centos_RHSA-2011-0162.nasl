#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0162 and 
# CentOS Errata and Security Advisory 2011:0162 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51786);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2010-3859", "CVE-2010-3876", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4242", "CVE-2010-4249");
  script_bugtraq_id(43806, 43809, 44354, 44630, 44648, 44758, 45014, 45037, 45054, 45058, 45063, 45073);
  script_osvdb_id(69013, 69522, 70226, 70379);
  script_xref(name:"RHSA", value:"2011:0162");

  script_name(english:"CentOS 4 : kernel (CESA-2011:0162)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and two bugs
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A heap overflow flaw was found in the Linux kernel's Transparent
Inter-Process Communication protocol (TIPC) implementation. A local,
unprivileged user could use this flaw to escalate their privileges.
(CVE-2010-3859, Important)

* Missing sanity checks were found in gdth_ioctl_alloc() in the gdth
driver in the Linux kernel. A local user with access to '/dev/gdth' on
a 64-bit system could use these flaws to cause a denial of service or
escalate their privileges. (CVE-2010-4157, Moderate)

* A NULL pointer dereference flaw was found in the Bluetooth HCI UART
driver in the Linux kernel. A local, unprivileged user could use this
flaw to cause a denial of service. (CVE-2010-4242, Moderate)

* A flaw was found in the Linux kernel's garbage collector for AF_UNIX
sockets. A local, unprivileged user could use this flaw to trigger a
denial of service (out-of-memory condition). (CVE-2010-4249, Moderate)

* Missing initialization flaws were found in the Linux kernel. A
local, unprivileged user could use these flaws to cause information
leaks. (CVE-2010-3876, CVE-2010-4072, CVE-2010-4073, CVE-2010-4075,
CVE-2010-4080, CVE-2010-4083, CVE-2010-4158, Low)

Red Hat would like to thank Alan Cox for reporting CVE-2010-4242;
Vegard Nossum for reporting CVE-2010-4249; Vasiliy Kulikov for
reporting CVE-2010-3876; Kees Cook for reporting CVE-2010-4072; and
Dan Rosenberg for reporting CVE-2010-4073, CVE-2010-4075,
CVE-2010-4080, CVE-2010-4083, and CVE-2010-4158.

This update also fixes the following bugs :

* A flaw was found in the Linux kernel where, if used in conjunction
with another flaw that can result in a kernel Oops, could possibly
lead to privilege escalation. It does not affect Red Hat Enterprise
Linux 4 as the sysctl panic_on_oops variable is turned on by default.
However, as a preventive measure if the variable is turned off by an
administrator, this update addresses the issue. Red Hat would like to
thank Nelson Elhage for reporting this vulnerability. (BZ#659568)

* On Intel I/O Controller Hub 9 (ICH9) hardware, jumbo frame support
is achieved by using page-based sk_buff buffers without any packet
split. The entire frame data is copied to the page(s) rather than some
to the skb->data area and some to the page(s) when performing a
typical packet-split. This caused problems with the filtering code and
frames were getting dropped before they were received by listening
applications. This bug could eventually lead to the IP address being
released and not being able to be re-acquired from DHCP if the MTU
(Maximum Transfer Unit) was changed (for an affected interface using
the e1000e driver). With this update, frames are no longer dropped and
an IP address is correctly re-acquired after a previous release.
(BZ#664667)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4809d629"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35f8bae8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.35.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
