#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1212 and 
# CentOS Errata and Security Advisory 2011:1212 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56271);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-2482", "CVE-2011-2491", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2519", "CVE-2011-2901");
  script_bugtraq_id(48538, 49141, 49370, 49373, 49375, 49408);
  script_xref(name:"RHSA", value:"2011:1212");

  script_name(english:"CentOS 5 : kernel (CESA-2011:1212)");
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

* A NULL pointer dereference flaw was found in the Linux kernel's
Stream Control Transmission Protocol (SCTP) implementation. A remote
attacker could send a specially crafted SCTP packet to a target
system, resulting in a denial of service. (CVE-2011-2482, Important)

* A flaw in the Linux kernel's client-side NFS Lock Manager (NLM)
implementation could allow a local, unprivileged user to cause a
denial of service. (CVE-2011-2491, Important)

* Buffer overflow flaws in the Linux kernel's netlink-based wireless
configuration interface implementation could allow a local user, who
has the CAP_NET_ADMIN capability, to cause a denial of service or
escalate their privileges on systems that have an active wireless
interface. (CVE-2011-2517, Important)

* A flaw was found in the way the Linux kernel's Xen hypervisor
implementation emulated the SAHF instruction. When using a
fully-virtualized guest on a host that does not use hardware assisted
paging (HAP), such as those running CPUs that do not have support for
(or those that have it disabled) Intel Extended Page Tables (EPT) or
AMD Virtualization (AMD-V) Rapid Virtualization Indexing (RVI), a
privileged guest user could trigger this flaw to cause the hypervisor
to crash. (CVE-2011-2519, Moderate)

* An off-by-one flaw was found in the __addr_ok() macro in the Linux
kernel's Xen hypervisor implementation when running on 64-bit systems.
A privileged guest user could trigger this flaw to cause the
hypervisor to crash. (CVE-2011-2901, Moderate)

* /proc/[PID]/io is world-readable by default. Previously, these files
could be read without any further restrictions. A local, unprivileged
user could read these files, belonging to other, possibly privileged
processes to gather confidential information, such as the length of a
password used in a process. (CVE-2011-2495, Low)

Red Hat would like to thank Vasily Averin for reporting CVE-2011-2491,
and Vasiliy Kulikov of Openwall for reporting CVE-2011-2495.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a20af007"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45ce19c5"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000308.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c53dd47"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52ddd884"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-274.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-274.3.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
