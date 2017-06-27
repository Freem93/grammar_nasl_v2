#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0581 and 
# CentOS Errata and Security Advisory 2008:0581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43698);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2008-2374");
  script_bugtraq_id(30105);
  script_xref(name:"RHSA", value:"2008:0581");

  script_name(english:"CentOS 4 / 5 : bluez-libs / bluez-utils (CESA-2008:0581)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bluez-libs and bluez-utils packages that fix a security flaw
are now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The bluez-libs package contains libraries for use in Bluetooth
applications. The bluez-utils package contains Bluetooth daemons and
utilities.

An input validation flaw was found in the Bluetooth Session
Description Protocol (SDP) packet parser used by the Bluez Bluetooth
utilities. A Bluetooth device with an already-established trust
relationship, or a local user registering a service record via a
UNIX(r) socket or D-Bus interface, could cause a crash, or possibly
execute arbitrary code with privileges of the hcid daemon.
(CVE-2008-2374)

Users of bluez-libs and bluez-utils are advised to upgrade to these
updated packages, which contains a backported patch to correct this
issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d3c7c62"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6c1e939"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1856a574"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bfc427c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bluez-libs and / or bluez-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-utils-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bluez-libs-2.10-3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bluez-libs-2.10-3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bluez-libs-devel-2.10-3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bluez-libs-devel-2.10-3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bluez-utils-2.10-2.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bluez-utils-2.10-2.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bluez-utils-cups-2.10-2.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bluez-utils-cups-2.10-2.4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"bluez-libs-3.7-1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bluez-libs-devel-3.7-1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bluez-utils-3.7-2.2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bluez-utils-cups-3.7-2.2.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
