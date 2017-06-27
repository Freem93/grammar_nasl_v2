#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0003 and 
# CentOS Errata and Security Advisory 2009:0003 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43723);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-4405", "CVE-2008-4993", "CVE-2008-5716");
  script_xref(name:"RHSA", value:"2009:0003");

  script_name(english:"CentOS 5 : xen (CESA-2009:0003)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that resolve several security issues and a bug
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The xen packages contain the Xen tools and management daemons needed
to manage virtual machines running on Red Hat Enterprise Linux.

Xen was found to allow unprivileged DomU domains to overwrite xenstore
values which should only be changeable by the privileged Dom0 domain.
An attacker controlling a DomU domain could, potentially, use this
flaw to kill arbitrary processes in Dom0 or trick a Dom0 user into
accessing the text console of a different domain running on the same
host. This update makes certain parts of the xenstore tree read-only
to the unprivileged DomU domains. (CVE-2008-4405)

It was discovered that the qemu-dm.debug script created a temporary
file in /tmp in an insecure way. A local attacker in Dom0 could,
potentially, use this flaw to overwrite arbitrary files via a symlink
attack. Note: This script is not needed in production deployments and
therefore was removed and is not shipped with updated xen packages.
(CVE-2008-4993)

This update also fixes the following bug :

* xen calculates its running time by adding the hypervisor's up-time
to the hypervisor's boot-time record. In live migrations of
para-virtualized guests, however, the guest would over-write the new
hypervisor's boot-time record with the boot-time of the previous
hypervisor. This caused time-dependent processes on the guests to fail
(for example, crond would fail to start cron jobs). With this update,
the new hypervisor's boot-time record is no longer over-written during
live migrations.

All xen users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. The Xen host must
be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7f29b60"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?061f6dfe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-64.el5_2.9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-64.el5_2.9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-64.el5_2.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
