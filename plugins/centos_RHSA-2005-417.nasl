#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:417 and 
# CentOS Errata and Security Advisory 2005:417 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21936);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1278", "CVE-2005-1279", "CVE-2005-1280");
  script_bugtraq_id(13380, 13389, 13390, 13392);
  script_osvdb_id(15862, 15863, 15864, 15904);
  script_xref(name:"RHSA", value:"2005:417");

  script_name(english:"CentOS 3 / 4 : tcpdump (CESA-2005:417)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tcpdump packages that fix several security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

This updated package also adds support for output files larger than 2
GB.

Tcpdump is a command-line tool for monitoring network traffic.

Several denial of service bugs were found in the way tcpdump processes
certain network packets. It is possible for an attacker to inject a
carefully crafted packet onto the network, crashing a running tcpdump
session. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2005-1278, CVE-2005-1279,
and CVE-2005-1280 to these issues.

The tcpdump utility can now write a file larger than 2 GB.

Users of tcpdump are advised to upgrade to these erratum packages,
which contain backported security patches and are not vulnerable to
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011648.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011651.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:arpwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"arpwatch-2.1a11-7.E3.5")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libpcap-0.7.2-7.E3.5")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tcpdump-3.7.2-7.E3.5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"arpwatch-2.1a13-9.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpcap-0.8.3-9.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tcpdump-3.8.2-9.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
