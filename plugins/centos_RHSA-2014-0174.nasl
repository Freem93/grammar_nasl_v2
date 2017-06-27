#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0174 and 
# CentOS Errata and Security Advisory 2014:0174 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72492);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/10 11:40:11 $");

  script_cve_id("CVE-2013-6492");
  script_bugtraq_id(65587);
  script_xref(name:"RHSA", value:"2014:0174");

  script_name(english:"CentOS 5 : piranha (CESA-2014:0174)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated piranha package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Piranha provides high-availability and load-balancing services for Red
Hat Enterprise Linux. The piranha packages contain various tools to
administer and configure the Linux Virtual Server (LVS), as well as
the heartbeat and failover components. LVS is a dynamically-adjusted
kernel routing mechanism that provides load balancing, primarily for
Web and FTP servers.

It was discovered that the Piranha Configuration Tool did not properly
restrict access to its web pages. A remote attacker able to connect to
the Piranha Configuration Tool web server port could use this flaw to
read or modify the LVS configuration without providing valid
administrative credentials. (CVE-2013-6492)

All piranha users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?052b60a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected piranha package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:piranha");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"piranha-0.8.4-26.el5_10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
