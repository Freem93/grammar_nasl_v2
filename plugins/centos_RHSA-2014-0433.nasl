#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0433 and 
# CentOS Errata and Security Advisory 2014:0433 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73712);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/27 19:04:08 $");

  script_cve_id("CVE-2012-6638", "CVE-2013-2888");
  script_bugtraq_id(62043, 65654);
  script_xref(name:"RHSA", value:"2014:0433");

  script_name(english:"CentOS 5 : kernel (CESA-2014:0433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues, three bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled TCP packets with both the SYN and FIN flags
set. A remote attacker could use this flaw to consume an excessive
amount of resources on the target system, potentially resulting in a
denial of service. (CVE-2012-6638, Moderate)

* A flaw was found in the way the Linux kernel handled HID (Human
Interface Device) reports with an out-of-bounds Report ID. An attacker
with physical access to the system could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-2888, Moderate)

This update also fixes the following bugs :

* A previous change to the sunrpc code introduced a race condition
between the rpc_wake_up_task() and rpc_wake_up_status() functions. A
race between threads operating on these functions could result in a
deadlock situation, subsequently triggering a 'soft lockup' event and
rendering the system unresponsive. This problem has been fixed by
re-ordering tasks in the RPC wait queue. (BZ#1073731)

* Running a process in the background on a GFS2 file system could
sometimes trigger a glock recursion error that resulted in a kernel
panic. This happened when a readpage operation attempted to take a
glock that had already been held by another function. To prevent this
error, GFS2 now verifies whether the glock is already held when
performing the readpage operation. (BZ#1073953)

* A previous patch backport to the IUCV (Inter User Communication
Vehicle) code was incomplete. Consequently, when establishing an IUCV
connection, the kernel could, under certain circumstances, dereference
a NULL pointer, resulting in a kernel panic. A patch has been applied
to correct this problem by calling the proper function when removing
IUCV paths. (BZ#1077045)

In addition, this update adds the following enhancement :

* The lpfc driver had a fixed timeout of 60 seconds for SCSI task
management commands. With this update, the lpfc driver enables the
user to set this timeout within the range from 5 to 180 seconds. The
timeout can be changed by modifying the 'lpfc_task_mgmt_tmo' parameter
for the lpfc driver. (BZ#1073123)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41cf54c2"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-371.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-371.8.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
