#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0241 and 
# CentOS Errata and Security Advisory 2013:0241 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64511);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/22 18:44:41 $");

  script_cve_id("CVE-2012-4544");
  script_bugtraq_id(56289);
  script_osvdb_id(86619);
  script_xref(name:"RHSA", value:"2013:0241");

  script_name(english:"CentOS 5 : xen (CESA-2013:0241)");
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
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xen packages contain administration tools and the xend service for
managing the kernel-xen kernel for virtualization on Red Hat
Enterprise Linux.

A flaw was found in the way libxc, the Xen control library, handled
excessively large kernel and ramdisk images when starting new guests.
A privileged guest user in a para-virtualized guest (a DomU) could
create a crafted kernel or ramdisk image that, when attempting to use
it during guest start, could result in an out-of-memory condition in
the privileged domain (the Dom0). (CVE-2012-4544)

Red Hat would like to thank the Xen project for reporting this issue.

All users of xen are advised to upgrade to these updated packages,
which correct this issue. After installing the updated packages, the
xend service must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9778e368"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-142.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-142.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-142.el5_9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
