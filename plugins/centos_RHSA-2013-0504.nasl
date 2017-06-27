#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0504 and 
# CentOS Errata and Security Advisory 2013:0504 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65139);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2012-3955");
  script_bugtraq_id(55530);
  script_osvdb_id(85424);
  script_xref(name:"RHSA", value:"2013:0504");

  script_name(english:"CentOS 6 : dhcp (CESA-2013:0504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix one security issue and two bugs are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The dhcp packages provide the Dynamic Host Configuration Protocol
(DHCP) that allows individual devices on an IP network to get their
own network configuration information, including an IP address, a
subnet mask, and a broadcast address.

A flaw was found in the way the dhcpd daemon handled the expiration
time of IPv6 leases. If dhcpd's configuration was changed to reduce
the default IPv6 lease time, lease renewal requests for previously
assigned leases could cause dhcpd to crash. (CVE-2012-3955)

This update also fixes the following bugs :

* Prior to this update, the DHCP server discovered only the first IP
address of a network interface if the network interface had more than
one configured IP address. As a consequence, the DHCP server failed to
restart if the server was configured to serve only a subnet of the
following IP addresses. This update modifies network interface
addresses discovery code to find all addresses of a network interface.
The DHCP server can also serve subnets of other addresses. (BZ#803540)

* Prior to this update, the dhclient rewrote the /etc/resolv.conf file
with backup data after it was stopped even when the PEERDNS flag was
set to 'no' before shut down if the configuration file was changed
while the dhclient ran with PEERDNS=yes. This update removes the
backing up and restoring functions for this configuration file from
the dhclient-script. Now, the dhclient no longer rewrites the
/etc/resolv.conf file when stopped. (BZ#824622)

All users of DHCP are advised to upgrade to these updated packages,
which fix these issues. After installing this update, all DHCP servers
will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1e226f0"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000501.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23ec93d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"dhclient-4.1.1-34.P1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-4.1.1-34.P1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-common-4.1.1-34.P1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dhcp-devel-4.1.1-34.P1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
