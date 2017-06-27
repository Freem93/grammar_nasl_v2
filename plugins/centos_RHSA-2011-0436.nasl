#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0436 and 
# CentOS Errata and Security Advisory 2011:0436 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53434);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-1002");
  script_bugtraq_id(46446);
  script_xref(name:"RHSA", value:"2011:0436");

  script_name(english:"CentOS 5 : avahi (CESA-2011:0436)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated avahi packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Avahi is an implementation of the DNS Service Discovery and Multicast
DNS specifications for Zero Configuration Networking. It facilitates
service discovery on a local network. Avahi and Avahi-aware
applications allow you to plug your computer into a network and, with
no configuration, view other people to chat with, view printers to
print to, and find shared files on other computers.

A flaw was found in the way the Avahi daemon (avahi-daemon) processed
Multicast DNS (mDNS) packets with an empty payload. An attacker on the
local network could use this flaw to cause avahi-daemon on a target
system to enter an infinite loop via an empty mDNS UDP packet.
(CVE-2011-1002)

All users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, avahi-daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?784f86d0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5b22cb1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"avahi-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-howl-devel-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-compat-libdns_sd-devel-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-devel-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-glib-devel-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-qt3-devel-0.6.16-10.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"avahi-tools-0.6.16-10.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
