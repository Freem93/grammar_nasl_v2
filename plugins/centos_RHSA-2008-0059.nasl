#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0059 and 
# CentOS Errata and Security Advisory 2008:0059 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30044);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6450", "CVE-2007-6451");
  script_bugtraq_id(24662, 26532, 27071);
  script_osvdb_id(37641, 40450, 40455);
  script_xref(name:"RHSA", value:"2008:0059");

  script_name(english:"CentOS 3 : wireshark (CESA-2008:0059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

Several flaws were found in Wireshark. Wireshark could crash or
possibly execute arbitrary code as the user running Wireshark if it
read a malformed packet off the network. (CVE-2007-6114,
CVE-2007-6115, CVE-2007-6117)

Several denial of service bugs were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off the
network. (CVE-2007-3389, CVE-2007-3390, CVE-2007-3391, CVE-2007-3392,
CVE-2007-3392, CVE-2007-3393, CVE-2007-6113, CVE-2007-6118,
CVE-2007-6120, CVE-2007-6121, CVE-2007-6450, CVE-2007-6451)

As well, Wireshark switched from using net-snmp to libsmi, which is
included in this errata.

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 0.99.7, and resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78a2c941"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e096f0a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014637.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf030054"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libsmi-0.4.5-3.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libsmi-devel-0.4.5-3.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-0.99.7-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-0.99.7-EL3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
