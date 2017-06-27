#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0599 and 
# CentOS Errata and Security Advisory 2013:0599 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65063);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/01 11:02:43 $");

  script_cve_id("CVE-2012-6075");
  script_bugtraq_id(57420);
  script_osvdb_id(89319);
  script_xref(name:"RHSA", value:"2013:0599");

  script_name(english:"CentOS 5 : xen (CESA-2013:0599)");
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

A flaw was found in the way QEMU emulated the e1000 network interface
card when the host was configured to accept jumbo network frames, and
a fully-virtualized guest using the e1000 emulated driver was not. A
remote attacker could use this flaw to crash the guest or,
potentially, execute arbitrary code with root privileges in the guest.
(CVE-2012-6075)

All users of xen are advised to upgrade to these updated packages,
which correct this issue. After installing the updated packages, all
running fully-virtualized guests must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9a5e2e7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-142.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-142.el5_9.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-142.el5_9.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
