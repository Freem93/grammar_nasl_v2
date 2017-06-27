#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1236 and 
# CentOS Errata and Security Advisory 2012:1236 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61791);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/01 11:02:43 $");

  script_cve_id("CVE-2012-3515");
  script_bugtraq_id(55413);
  script_xref(name:"RHSA", value:"2012:1236");

  script_name(english:"CentOS 5 : xen (CESA-2012:1236)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that fix one security issue are now available for
Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The xen packages contain administration tools and the xend service for
managing the kernel-xen kernel for virtualization on Red Hat
Enterprise Linux.

A flaw was found in the way QEMU handled VT100 terminal escape
sequences when emulating certain character devices. A guest user with
privileges to write to a character device that is emulated on the host
using a virtual console back-end could use this flaw to crash the qemu
process on the host or, possibly, escalate their privileges on the
host. (CVE-2012-3515)

This flaw did not affect the default use of the Xen hypervisor
implementation in Red Hat Enterprise Linux 5. This problem only
affected fully-virtualized guests that have a serial or parallel
device that uses a virtual console (vc) back-end. By default, the
virtual console back-end is not used for such devices; only guests
explicitly configured to use them in this way were affected.

Red Hat would like to thank the Xen project for reporting this issue.

All users of xen are advised to upgrade to these updated packages,
which correct this issue. After installing the updated packages, all
fully-virtualized guests must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d41bd61"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-135.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-135.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-135.el5_8.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
