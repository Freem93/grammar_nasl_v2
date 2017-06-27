#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0323 and 
# CentOS Errata and Security Advisory 2007:0323 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43639);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-4993");
  script_bugtraq_id(23731);
  script_osvdb_id(35494, 35495, 41340);
  script_xref(name:"RHSA", value:"2007:0323");

  script_name(english:"CentOS 5 : xen (CESA-2007:0323)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Xen package to fix multiple security issues is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Xen package contains the tools for managing the virtual machine
monitor in Red Hat Enterprise Linux virtualization.

The following security flaws are fixed in the updated Xen package :

Joris van Rantwijk found a flaw in the Pygrub utility which is used as
a boot loader for guest domains. A malicious local administrator of a
guest domain could create a carefully crafted grub.conf file which
would trigger the execution of arbitrary code outside of that domain.
(CVE-2007-4993)

Tavis Ormandy discovered a heap overflow flaw during video-to-video
copy operations in the Cirrus VGA extension code used in Xen. A
malicious local administrator of a guest domain could potentially
trigger this flaw and execute arbitrary code outside of the domain.
(CVE-2007-1320)

Tavis Ormandy discovered insufficient input validation leading to a
heap overflow in the Xen NE2000 network driver. If the driver is in
use, a malicious local administrator of a guest domain could
potentially trigger this flaw and execute arbitrary code outside of
the domain. Xen does not use this driver by default. (CVE-2007-1321)

Users of Xen should update to these erratum packages containing
backported patches which correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?900c3de5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d9099cd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
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
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-25.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-25.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-25.0.4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
