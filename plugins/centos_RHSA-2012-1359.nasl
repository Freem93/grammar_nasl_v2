#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1359 and 
# CentOS Errata and Security Advisory 2012:1359 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62520);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-4423");
  script_bugtraq_id(55541);
  script_osvdb_id(86205);
  script_xref(name:"RHSA", value:"2012:1359");

  script_name(english:"CentOS 6 : libvirt (CESA-2012:1359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue and multiple bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

A flaw was found in libvirtd's RPC call handling. An attacker able to
establish a read-only connection to libvirtd could use this flaw to
crash libvirtd by sending an RPC message that has an event as the RPC
number, or an RPC number that falls into a gap in the RPC dispatch
table. (CVE-2012-4423)

This issue was discovered by Wenlong Huang of the Red Hat
Virtualization QE Team.

This update also fixes the following bugs :

* When the host_uuid option was present in the libvirtd.conf file, the
augeas libvirt lens was unable to parse the file. This bug has been
fixed and the augeas libvirt lens now parses libvirtd.conf as expected
in the described scenario. (BZ#858988)

* Disk hot plug is a two-part action: the qemuMonitorAddDrive() call
is followed by the qemuMonitorAddDevice() call. When the first part
succeeded but the second one failed, libvirt failed to roll back the
first part and the device remained in use even though the disk hot
plug failed. With this update, the rollback for the drive addition is
properly performed in the described scenario and disk hot plug now
works as expected. (BZ#859376)

* When a virtual machine was started with an image chain using block
devices and a block rebase operation was issued, the operation failed
on completion in the blockJobAbort() function. This update relabels
and configures cgroups for the backing files and the rebase operation
now succeeds. (BZ#860720)

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7004f229"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.9.10-21.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.9.10-21.el6_3.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
