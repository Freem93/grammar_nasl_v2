#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1141 and 
# CentOS Errata and Security Advisory 2012:1141 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61437);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/22 14:13:26 $");

  script_cve_id("CVE-2012-3571", "CVE-2012-3954");
  script_bugtraq_id(54665);
  script_osvdb_id(84253, 84255);
  script_xref(name:"RHSA", value:"2012:1141");

  script_name(english:"CentOS 6 : dhcp (CESA-2012:1141)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

A denial of service flaw was found in the way the dhcpd daemon handled
zero-length client identifiers. A remote attacker could use this flaw
to send a specially crafted request to dhcpd, possibly causing it to
enter an infinite loop and consume an excessive amount of CPU time.
(CVE-2012-3571)

Two memory leak flaws were found in the dhcpd daemon. A remote
attacker could use these flaws to cause dhcpd to exhaust all available
memory by sending a large number of DHCP requests. (CVE-2012-3954)

Upstream acknowledges Markus Hietava of the Codenomicon CROSS project
as the original reporter of CVE-2012-3571, and Glen Eustace of Massey
University, New Zealand, as the original reporter of CVE-2012-3954.

Users of DHCP should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing this
update, all DHCP servers will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fedfe59"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"dhclient-4.1.1-31.P1.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-4.1.1-31.P1.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-common-4.1.1-31.P1.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-devel-4.1.1-31.P1.el6_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
