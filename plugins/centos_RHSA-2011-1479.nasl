#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1479 and 
# CentOS Errata and Security Advisory 2011:1479 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67086);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-1898", "CVE-2011-2203", "CVE-2011-2494", "CVE-2011-3363", "CVE-2011-4110");
  script_bugtraq_id(48236, 48515, 49626, 50314, 50755, 50764);
  script_osvdb_id(75175, 75580, 76796, 77292, 77450, 77658);
  script_xref(name:"RHSA", value:"2011:1479");

  script_name(english:"CentOS 5 : kernel (CESA-2011:1479)");
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
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* Using PCI passthrough without interrupt remapping support allowed
Xen hypervisor guests to generate MSI interrupts and thus potentially
inject traps. A privileged guest user could use this flaw to crash the
host or possibly escalate their privileges on the host. The fix for
this issue can prevent PCI passthrough working and guests starting.
Refer to Red Hat Bugzilla bug 715555 for details. (CVE-2011-1898,
Important)

* A flaw was found in the way CIFS (Common Internet File System)
shares with DFS referrals at their root were handled. An attacker on
the local network who is able to deploy a malicious CIFS server could
create a CIFS network share that, when mounted, would cause the client
system to crash. (CVE-2011-3363, Moderate)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's key management facility handled user-defined key types. A
local, unprivileged user could use the keyctl utility to cause a
denial of service. (CVE-2011-4110, Moderate)

* A flaw in the way memory containing security-related data was
handled in tpm_read() could allow a local, unprivileged user to read
the results of a previously run TPM command. (CVE-2011-1162, Low)

* A NULL pointer dereference flaw was found in the Linux kernel's HFS
file system implementation. A local attacker could use this flaw to
cause a denial of service by mounting a disk that contains a specially
crafted HFS file system with a corrupted MDB extent record.
(CVE-2011-2203, Low)

* The I/O statistics from the taskstats subsystem could be read
without any restrictions. A local, unprivileged user could use this
flaw to gather confidential information, such as the length of a
password used in a process. (CVE-2011-2494, Low)

Red Hat would like to thank Yogesh Sharma for reporting CVE-2011-3363;
Peter Huewe for reporting CVE-2011-1162; Clement Lecigne for reporting
CVE-2011-2203; and Vasiliy Kulikov of Openwall for reporting
CVE-2011-2494.

This update also fixes several bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47b434d4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67a6a90d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
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
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-274.12.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-274.12.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
