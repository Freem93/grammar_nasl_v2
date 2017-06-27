#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0313 and 
# CentOS Errata and Security Advisory 2009:0313 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35767);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285", "CVE-2008-6472", "CVE-2009-0599", "CVE-2009-0600");
  script_bugtraq_id(31838, 32422);
  script_osvdb_id(49340, 49341, 49342, 49343, 49344, 51815, 51987);
  script_xref(name:"RHSA", value:"2009:0313");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2009:0313)");
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

Multiple buffer overflow flaws were found in Wireshark. If Wireshark
read a malformed packet off a network or opened a malformed dump file,
it could crash or, possibly, execute arbitrary code as the user
running Wireshark. (CVE-2008-4683, CVE-2009-0599)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malformed dump file. (CVE-2008-4680,
CVE-2008-4681, CVE-2008-4682, CVE-2008-4684, CVE-2008-4685,
CVE-2008-5285, CVE-2009-0600)

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.6, and resolve these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a48af50"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015801.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2705c65b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015651.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d8be16a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015652.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71c7e79f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015656.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b77f3f64"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdfab144"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/05");
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
if (rpm_check(release:"CentOS-3", reference:"wireshark-1.0.6-EL3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-1.0.6-EL3.3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-1.0.6-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"wireshark-1.0.6-2.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-1.0.6-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-1.0.6-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"wireshark-gnome-1.0.6-2.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-1.0.6-2.el4_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
