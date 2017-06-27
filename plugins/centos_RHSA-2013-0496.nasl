#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0496 and 
# CentOS Errata and Security Advisory 2013:0496 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65134);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2012-4508", "CVE-2012-4542", "CVE-2013-0190", "CVE-2013-0309", "CVE-2013-0310", "CVE-2013-0311");
  script_bugtraq_id(56238, 57433, 58046, 58052, 58053, 58088);
  script_osvdb_id(88156, 90475, 90476);
  script_xref(name:"RHSA", value:"2013:0496");

  script_name(english:"CentOS 6 : kernel (CESA-2013:0496)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 6. This is the fourth regular update.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A race condition was found in the way asynchronous I/O and
fallocate() interacted when using the ext4 file system. A local,
unprivileged user could use this flaw to expose random data from an
extent whose data blocks have not yet been written, and thus contain
data from a deleted file. (CVE-2012-4508, Important)

* A flaw was found in the way the vhost kernel module handled
descriptors that spanned multiple regions. A privileged guest user in
a KVM guest could use this flaw to crash the host or, potentially,
escalate their privileges on the host. (CVE-2013-0311, Important)

* It was found that the default SCSI command filter does not
accommodate commands that overlap across device classes. A privileged
guest user could potentially use this flaw to write arbitrary data to
a LUN that is passed-through as read-only. (CVE-2012-4542, Moderate)

* A flaw was found in the way the xen_failsafe_callback() function in
the Linux kernel handled the failed iret (interrupt return)
instruction notification from the Xen hypervisor. An unprivileged user
in a 32-bit para-virtualized guest could use this flaw to crash the
guest. (CVE-2013-0190, Moderate)

* A flaw was found in the way pmd_present() interacted with PROT_NONE
memory ranges when transparent hugepages were in use. A local,
unprivileged user could use this flaw to crash the system.
(CVE-2013-0309, Moderate)

* A flaw was found in the way CIPSO (Common IP Security Option) IP
options were validated when set from user mode. A local user able to
set CIPSO IP options on the socket could use this flaw to crash the
system. (CVE-2013-0310, Moderate)

Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508,
and Andrew Cooper of Citrix for reporting CVE-2013-0190. Upstream
acknowledges Dmitry Monakhov as the original reporter of
CVE-2012-4508. The CVE-2012-4542 issue was discovered by Paolo Bonzini
of Red Hat.

This update also fixes several hundred bugs and adds enhancements.
Refer to the Red Hat Enterprise Linux 6.4 Release Notes for
information on the most significant of these changes, and the
Technical Notes for further information, both linked to in the
References.

All Red Hat Enterprise Linux 6 users are advised to install these
updated packages, which correct these issues, and fix the bugs and add
the enhancements noted in the Red Hat Enterprise Linux 6.4 Release
Notes and Technical Notes. The system must be rebooted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?431960d1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98338fc5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-358.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-358.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
