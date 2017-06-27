#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0387 and 
# CentOS Errata and Security Advisory 2007:0387 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67051);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1218", "CVE-2007-3798");
  script_bugtraq_id(24965);
  script_xref(name:"RHSA", value:"2007:0387");

  script_name(english:"CentOS 4 : tcpdump (CESA-2007:0387)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tcpdump packages that fix a security issue and functionality
bugs are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tcpdump is a command line tool for monitoring network traffic.

Moritz Jodeit discovered a denial of service bug in the tcpdump IEEE
802.11 processing code. An attacker could inject a carefully crafted
frame onto the IEEE 802.11 network that could crash a running tcpdump
session if a certain link type was explicitly specified.
(CVE-2007-1218)

An integer overflow flaw was found in tcpdump's BGP processing code.
An attacker could execute arbitrary code with the privilege of the
pcap user by injecting a crafted frame onto the network.
(CVE-2007-3798)

In addition, the following bugs have been addressed :

* if called with -C and -W switches, tcpdump would create the first
savefile with the privileges of the user that executed tcpdump
(usually root), rather than with ones of the pcap user. This could
result in the inability to save the complete traffic log file properly
without the immediate notice of the user running tcpdump.

* the arpwatch service initialization script would exit prematurely,
returning a successful exit status incorrectly and preventing the
status command from running in case networking is not available.

Users of tcpdump are advised to upgrade to these erratum packages,
which contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b123eca6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:arpwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"arpwatch-2.1a13-12.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpcap-0.8.3-12.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tcpdump-3.8.2-12.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
