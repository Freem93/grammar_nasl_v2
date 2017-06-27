#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1401 and 
# CentOS Errata and Security Advisory 2011:1401 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56621);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3346");
  script_bugtraq_id(49545);
  script_xref(name:"RHSA", value:"2011:1401");

  script_name(english:"CentOS 5 : xen (CESA-2011:1401)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xen packages contain administration tools and the xend service for
managing the kernel-xen kernel for virtualization on Red Hat
Enterprise Linux.

A buffer overflow flaw was found in the Xen hypervisor SCSI subsystem
emulation. An unprivileged, local guest user could provide a large
number of bytes that are used to zero out a fixed-sized buffer via a
SAI READ CAPACITY SCSI command, overwriting memory and causing the
guest to crash. (CVE-2011-3346)

This update also fixes the following bugs :

* Prior to this update, the vif-bridge script used a maximum
transmission unit (MTU) of 1500 for a new Virtual Interface (VIF). As
a result, the MTU of the VIF could differ from that of the target
bridge. This update fixes the VIF hot-plug script so that the default
MTU for new VIFs will match that of the target Xen hypervisor bridge.
In combination with a new enough kernel (RHSA-2011:1386), this enables
the use of jumbo frames in Xen hypervisor guests. (BZ#738608)

* Prior to this update, the network-bridge script set the MTU of the
bridge to 1500. As a result, the MTU of the Xen hypervisor bridge
could differ from that of the physical interface. This update fixes
the network script so the MTU of the bridge can be set higher than
1500, thus also providing support for jumbo frames. Now, the MTU of
the Xen hypervisor bridge will match that of the physical interface.
(BZ#738610)

* Red Hat Enterprise Linux 5.6 introduced an optimized migration
handling that speeds up the migration of guests with large memory.
However, the new migration procedure can theoretically cause data
corruption. While no cases were observed in practice, with this
update, the xend daemon properly waits for correct device release
before the guest is started on a destination machine, thus fixing this
bug. (BZ#743850)

Note: Before a guest is using a new enough kernel (RHSA-2011:1386),
the MTU of the VIF will drop back to 1500 (if it was set higher) after
migration.

All xen users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the xend service must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcfd2bb0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff44307e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/25");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-132.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-132.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-132.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
