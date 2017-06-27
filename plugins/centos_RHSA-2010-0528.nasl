#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0528 and 
# CentOS Errata and Security Advisory 2010:0528 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47739);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_bugtraq_id(33946, 41075);
  script_xref(name:"RHSA", value:"2010:0528");

  script_name(english:"CentOS 5 : avahi (CESA-2010:0528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated avahi packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Avahi is an implementation of the DNS Service Discovery and Multicast
DNS specifications for Zero Configuration Networking. It facilitates
service discovery on a local network. Avahi and Avahi-aware
applications allow you to plug your computer into a network and, with
no configuration, view other people to chat with, view printers to
print to, and find shared files on other computers.

A flaw was found in the way the Avahi daemon (avahi-daemon) processed
Multicast DNS (mDNS) packets with corrupted checksums. An attacker on
the local network could use this flaw to cause avahi-daemon on a
target system to exit unexpectedly via specially crafted mDNS packets.
(CVE-2010-2244)

A flaw was found in the way avahi-daemon processed incoming unicast
mDNS messages. If the mDNS reflector were enabled on a system, an
attacker on the local network could send a specially crafted unicast
mDNS message to that system, resulting in its avahi-daemon flooding
the network with a multicast packet storm, and consuming a large
amount of CPU. Note: The mDNS reflector is disabled by default.
(CVE-2009-0758)

All users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, avahi-daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1464d40"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c93b139b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"avahi-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
