#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1790 and 
# CentOS Errata and Security Advisory 2013:1790 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71236);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/12/11 16:09:55 $");

  script_cve_id("CVE-2013-4355");
  script_bugtraq_id(62708);
  script_osvdb_id(97955);
  script_xref(name:"RHSA", value:"2013:1790");

  script_name(english:"CentOS 5 : kernel (CESA-2013:1790)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* An information leak flaw was found in the way the Xen hypervisor
handled error conditions when reading guest memory during certain
guest-originated operations, such as port or memory mapped I/O writes.
A privileged user in a fully-virtualized guest could use this flaw to
leak hypervisor stack memory to a guest. (CVE-2013-4355, Moderate)

Red Hat would like to thank the Xen project for reporting this issue.

This update also fixes the following bugs :

* A previous fix to the kernel did not contain a memory barrier in the
percpu_up_write() function. Consequently, under certain circumstances,
a race condition could occur leading to memory corruption and a
subsequent kernel panic. This update introduces a new memory barrier
pair, light_mb() and heavy_mb(), for per-CPU basis read and write
semaphores (percpu-rw-semaphores) ensuring that the race condition can
no longer occur. In addition, the read path performance of
'percpu-rw-semaphores' has been improved. (BZ#1014715)

* Due to a bug in the tg3 driver, systems that had the Wake-on-LAN
(WOL) feature enabled on their NICs could not have been woken up from
suspension or hibernation using WOL. A missing pci_wake_from_d3()
function call has been added to the tg3 driver, which ensures that WOL
functions properly by setting the PME_ENABLE bit. (BZ#1014973)

* Due to an incorrect test condition in the mpt2sas driver, the driver
was unable to catch failures to map a SCSI scatter-gather list. The
test condition has been corrected so that the mpt2sas driver now
handles SCSI scatter-gather mapping failures as expected. (BZ#1018458)

* A previous patch to the kernel introduced the 'VLAN tag
re-insertion' workaround to resolve a problem with incorrectly handled
VLAN-tagged packets with no assigned VLAN group while the be2net
driver was in promiscuous mode. However, this solution led to packet
corruption and a subsequent kernel oops if such a processed packed was
a GRO packet. Therefore, a patch has been applied to restrict VLAN tag
re-insertion only to non-GRO packets. The be2net driver now processes
VLAN-tagged packets with no assigned VLAN group correctly in this
situation. (BZ#1023348)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77843807"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:N/A:N");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/06");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-371.3.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
