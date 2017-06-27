#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0833 and 
# CentOS Errata and Security Advisory 2011:0833 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67081);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:23 $");

  script_cve_id("CVE-2011-0726", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1763");
  script_bugtraq_id(46616, 46793, 46878, 46919, 47185, 47343, 47791, 48048);
  script_xref(name:"RHSA", value:"2011:0833");

  script_name(english:"CentOS 5 : kernel (CESA-2011:0833)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw in the dccp_rcv_state_process() function could allow a remote
attacker to cause a denial of service, even when the socket was
already closed. (CVE-2011-1093, Important)

* Multiple buffer overflow flaws were found in the Linux kernel's
Management Module Support for Message Passing Technology (MPT) based
controllers. A local, unprivileged user could use these flaws to cause
a denial of service, an information leak, or escalate their
privileges. (CVE-2011-1494, CVE-2011-1495, Important)

* A missing validation of a null-terminated string data structure
element in the bnep_sock_ioctl() function could allow a local user to
cause an information leak or a denial of service. (CVE-2011-1079,
Moderate)

* Missing error checking in the way page tables were handled in the
Xen hypervisor implementation could allow a privileged guest user to
cause the host, and the guests, to lock up. (CVE-2011-1166, Moderate)

* A flaw was found in the way the Xen hypervisor implementation
checked for the upper boundary when getting a new event channel port.
A privileged guest user could use this flaw to cause a denial of
service or escalate their privileges. (CVE-2011-1763, Moderate)

* The start_code and end_code values in '/proc/[pid]/stat' were not
protected. In certain scenarios, this flaw could be used to defeat
Address Space Layout Randomization (ASLR). (CVE-2011-0726, Low)

* A missing initialization flaw in the sco_sock_getsockopt() function
could allow a local, unprivileged user to cause an information leak.
(CVE-2011-1078, Low)

* A missing validation of a null-terminated string data structure
element in the do_replace() function could allow a local user who has
the CAP_NET_ADMIN capability to cause an information leak.
(CVE-2011-1080, Low)

* A buffer overflow flaw in the DEC Alpha OSF partition implementation
in the Linux kernel could allow a local attacker to cause an
information leak by mounting a disk that contains specially crafted
partition tables. (CVE-2011-1163, Low)

* Missing validations of null-terminated string data structure
elements in the do_replace(), compat_do_replace(), do_ipt_get_ctl(),
do_ip6t_get_ctl(), and do_arpt_get_ctl() functions could allow a local
user who has the CAP_NET_ADMIN capability to cause an information
leak. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, Low)

* A heap overflow flaw in the Linux kernel's EFI GUID Partition Table
(GPT) implementation could allow a local attacker to cause a denial of
service by mounting a disk that contains specially crafted partition
tables. (CVE-2011-1577, Low)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2011-1494
and CVE-2011-1495; Vasiliy Kulikov for reporting CVE-2011-1079,
CVE-2011-1078, CVE-2011-1080, CVE-2011-1170, CVE-2011-1171, and
CVE-2011-1172; Kees Cook for reporting CVE-2011-0726; and Timo Warns
for reporting CVE-2011-1163 and CVE-2011-1577.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017610.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-238.12.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
