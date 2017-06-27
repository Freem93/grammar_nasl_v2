#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1100 and 
# CentOS Errata and Security Advisory 2009:1100 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39423);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-1829");
  script_bugtraq_id(34291, 34457, 35081);
  script_xref(name:"RHSA", value:"2009:1100");

  script_name(english:"CentOS 3 / 5 : wireshark (CESA-2009:1100)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

A format string flaw was found in Wireshark. If Wireshark read a
malformed packet off a network or opened a malicious dump file, it
could crash or, possibly, execute arbitrary code as the user running
Wireshark. (CVE-2009-1210)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2009-1268,
CVE-2009-1269, CVE-2009-1829)

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.8, and resolve these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a5f970e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fc068c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?062556a8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92f69038"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-gnome-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-gnome-1.0.8-EL3.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.8-1.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.8-1.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
