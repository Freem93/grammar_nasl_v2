#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1409 and 
# CentOS Errata and Security Advisory 2013:1409 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70344);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-4342");
  script_bugtraq_id(62871);
  script_xref(name:"RHSA", value:"2013:1409");

  script_name(english:"CentOS 5 / 6 : xinetd (CESA-2013:1409)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xinetd package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xinetd package provides a secure replacement for inetd, the
Internet services daemon. xinetd provides access control for all
services based on the address of the remote host and/or on time of
access, and can prevent denial-of-access attacks.

It was found that xinetd ignored the user and group configuration
directives for services running under the tcpmux-server service. This
flaw could cause the associated services to run as root. If there was
a flaw in such a service, a remote attacker could use it to execute
arbitrary code with the privileges of the root user. (CVE-2013-4342)

Red Hat would like to thank Thomas Swan of FedEx for reporting this
issue.

All xinetd users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-October/019967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bdea156"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-October/000887.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b30fe1cb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xinetd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xinetd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"xinetd-2.3.14-20.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"xinetd-2.3.14-39.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
