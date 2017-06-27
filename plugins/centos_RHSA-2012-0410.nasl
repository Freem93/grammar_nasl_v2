#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0410 and 
# CentOS Errata and Security Advisory 2012:0410 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58457);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/09/02 15:06:42 $");

  script_cve_id("CVE-2012-0037");
  script_bugtraq_id(52681);
  script_osvdb_id(80307);
  script_xref(name:"RHSA", value:"2012:0410");

  script_name(english:"CentOS 6 : raptor (CESA-2012:0410)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated raptor packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Raptor provides parsers for Resource Description Framework (RDF)
files.

An XML External Entity expansion flaw was found in the way Raptor
processed RDF files. If an application linked against Raptor were to
open a specially crafted RDF file, it could possibly allow a remote
attacker to obtain a copy of an arbitrary local file that the user
running the application had access to. A bug in the way Raptor handled
external entities could cause that application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-0037)

Red Hat would like to thank Timothy D. Morgan of VSR for reporting
this issue.

All Raptor users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications linked against Raptor must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-March/018518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c90fc902"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected raptor packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:raptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:raptor-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"raptor-1.4.18-5.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"raptor-devel-1.4.18-5.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
