#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1160 and 
# CentOS Errata and Security Advisory 2011:1160 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55860);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-2748", "CVE-2011-2749");
  script_bugtraq_id(49120);
  script_osvdb_id(74556, 74557);
  script_xref(name:"RHSA", value:"2011:1160");

  script_name(english:"CentOS 4 / 5 : dhcp (CESA-2011:1160)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix two security issues are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

Two denial of service flaws were found in the way the dhcpd daemon
handled certain incomplete request packets. A remote attacker could
use these flaws to crash dhcpd via a specially crafted request.
(CVE-2011-2748, CVE-2011-2749)

Users of DHCP should upgrade to these updated packages, which contain
a backported patch to correct these issues. After installing this
update, all DHCP servers will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b036c40"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04156f84"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?549f5c83"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e90062a"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51121df5"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18934e98"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhclient-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhclient-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-devel-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-devel-3.0.1-68.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"dhclient-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-devel-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-devel-3.0.5-29.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
