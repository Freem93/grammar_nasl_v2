#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1106. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63994);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/13 15:17:28 $");

  script_cve_id("CVE-2011-1576");
  script_bugtraq_id(48907);
  script_osvdb_id(74655);
  script_xref(name:"RHSA", value:"2011:1106");

  script_name(english:"RHEL 6 : kernel (RHSA-2011:1106)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.0 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* A flaw allowed napi_reuse_skb() to be called on VLAN (virtual LAN)
packets. An attacker on the local network could trigger this flaw by
sending specially crafted packets to a target system, possibly causing
a denial of service. (CVE-2011-1576, Moderate)

Red Hat would like to thank Ryan Sweat for reporting this issue.

This update also fixes the following bugs :

* The LSI SAS2 controller firmware issued an 0x620f fault while
performing I/O operations and with a Task Manager running, causing
possible data corruption. This update corrects this issue. (BZ#710625)

* The crashkernel memory region can overlap the RunTime Abstraction
Services (RTAS) memory region. If the crashkernel memory region was
freed, the RTAS memory region was freed as well and the system would
crash. With this update, the crash_free_reserved_phys_range() function
is overridden and overlaps with the RTAS memory region are checked so
that system crashes no longer occur. (BZ#710626)

* If the microcode module was loaded, saving and restoring a Xen guest
returned a warning message and a backtrace error. With this update,
backtrace errors are no longer returned, and saving and restoring a
Xen guest works as expected. (BZ#710632)

* When the Distributed Lock Manager (DLM) queued three callbacks for a
lock in the following sequence: blocking - completion - blocking, it
would consider the final blocking callback redundant and skip it.
Because the callback was skipped, GFS would not release the lock,
causing processes on other nodes to wait indefinitely for it. With
this update, the DLM does not skip the necessary blocking callback.
(BZ#710642)

* The XFRM_SUB_POLICY feature causes all bundles to be at the finest
granularity possible. As a result of the data structure used to
implement this, the system performance would drop considerably. This
update disables a part of XFRM_SUB_POLICY, eliminating the poor
performance at the cost of sub-IP address selection granularity in the
policy. (BZ#710645)

* A kernel panic in the mpt2sas driver could occur on an IBM system
using a drive with SMART (Self-Monitoring, Analysis and Reporting
Technology) issues. This was because the driver was sending an SEP
request while the kernel was in the interrupt context, causing the
driver to enter the sleep state. With this update, a fake event is now
executed from the interrupt context, assuring the SEP request is
properly issued. (BZ#714189)

Finally, this update provides the following enhancements :

* This update introduces a kernel module option that allows the Flow
Director to be disabled. (BZ#711549)

* This update introduces parallel port printer support for Red Hat
Enterprise Linux 6. (BZ#713825)

* This update restricts access to the /proc/kcore file to ELF headers
only. (BZ#710638)

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues and add these enhancements.
The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1106.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-71.34.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"perf-2.6.32-71.34.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
