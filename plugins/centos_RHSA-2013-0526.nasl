#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0526 and 
# CentOS Errata and Security Advisory 2013:0526 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65156);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-3386");
  script_bugtraq_id(54418);
  script_xref(name:"RHSA", value:"2013:0526");

  script_name(english:"CentOS 6 : automake (CESA-2013:0526)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated automake package that fixes one security issue is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Automake is a tool for automatically generating Makefile.in files
compliant with the GNU Coding Standards.

It was found that the distcheck rule in Automake-generated Makefiles
made a directory world-writable when preparing source archives. If a
malicious, local user could access this directory, they could execute
arbitrary code with the privileges of the user running 'make
distcheck'. (CVE-2012-3386)

Red Hat would like to thank Jim Meyering for reporting this issue.
Upstream acknowledges Stefano Lattarini as the original reporter.

Users of automake are advised to upgrade to this updated package,
which corrects this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25090270"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?328379f5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected automake package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:automake");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
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
if (rpm_check(release:"CentOS-6", reference:"automake-1.11.1-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
