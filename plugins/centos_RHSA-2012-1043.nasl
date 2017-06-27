#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1043 and 
# CentOS Errata and Security Advisory 2012:1043 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59737);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/04 15:13:48 $");

  script_cve_id("CVE-2012-2149");
  script_bugtraq_id(53570);
  script_osvdb_id(81989);
  script_xref(name:"RHSA", value:"2012:1043");

  script_name(english:"CentOS 5 : libwpd (CESA-2012:1043)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libwpd packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

libwpd is a library for reading and converting Corel WordPerfect
Office documents.

A buffer overflow flaw was found in the way libwpd processed certain
Corel WordPerfect Office documents (.wpd files). An attacker could
provide a specially crafted .wpd file that, when opened in an
application linked against libwpd, such as OpenOffice.org, would cause
the application to crash or, potentially, execute arbitrary code with
the privileges of the user running the application. (CVE-2012-2149)

All libwpd users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications that are linked against libwpd must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018700.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d429e90"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwpd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libwpd-0.8.7-3.1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libwpd-devel-0.8.7-3.1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libwpd-tools-0.8.7-3.1.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
