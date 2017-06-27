#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0218 and 
# CentOS Errata and Security Advisory 2013:0218 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64385);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/29 00:03:03 $");

  script_cve_id("CVE-2013-0241");
  script_osvdb_id(89731);
  script_xref(name:"RHSA", value:"2013:0218");

  script_name(english:"CentOS 6 : xorg-x11-drv-qxl (CESA-2013:0218)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xorg-x11-drv-qxl package that fixes one security issue is
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xorg-x11-drv-qxl package provides an X11 video driver for the QEMU
QXL video accelerator. This driver makes it possible to use Red Hat
Enterprise Linux 6 as a guest operating system under the KVM kernel
module and the QEMU multi-platform emulator, using the SPICE protocol.

A flaw was found in the way the host's qemu-kvm qxl driver and the
guest's X.Org qxl driver interacted when a SPICE connection
terminated. A user able to initiate a SPICE connection to a guest
could use this flaw to make the guest temporarily unavailable or,
potentially (if the sysctl kernel.softlockup_panic variable was set to
'1' in the guest), crash the guest. (CVE-2013-0241)

All users of xorg-x11-drv-qxl are advised to upgrade to this updated
package, which contains a backported patch to correct this issue. All
running X.Org server instances using the qxl driver must be restarted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d7edbda"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-drv-qxl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
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
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-drv-qxl-0.0.14-14.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
