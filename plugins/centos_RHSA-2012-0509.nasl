#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0509 and 
# CentOS Errata and Security Advisory 2012:0509 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58849);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/27 15:42:52 $");

  script_cve_id("CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-1595");
  script_bugtraq_id(46796, 47392, 48066, 48506, 49071, 50486, 51368, 51710, 52737);
  script_osvdb_id(71548, 71846, 72975, 72976, 72977, 72978, 72979, 73687, 74731, 76770, 78256, 78258, 78656, 78657, 80713);
  script_xref(name:"RHSA", value:"2012:0509");

  script_name(english:"CentOS 6 : wireshark (CESA-2012:0509)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

Several flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2011-1590, CVE-2011-4102, CVE-2012-1595)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2011-1143,
CVE-2011-1957, CVE-2011-1958, CVE-2011-1959, CVE-2011-2174,
CVE-2011-2175, CVE-2011-2597, CVE-2011-2698, CVE-2012-0041,
CVE-2012-0042, CVE-2012-0067, CVE-2012-0066)

Users of Wireshark should upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54ae5382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
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
if (rpm_check(release:"CentOS-6", reference:"wireshark-1.2.15-2.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"wireshark-devel-1.2.15-2.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"wireshark-gnome-1.2.15-2.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
