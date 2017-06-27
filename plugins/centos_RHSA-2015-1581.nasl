#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1581 and 
# CentOS Errata and Security Advisory 2015:1581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85306);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/30 15:53:11 $");

  script_cve_id("CVE-2015-4495");
  script_osvdb_id(125839);
  script_xref(name:"RHSA", value:"2015:1581");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2015:1581)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix one security issue are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A flaw was discovered in Mozilla Firefox that could be used to violate
the same-origin policy and inject web script into a non-privileged
part of the built-in PDF file viewer (PDF.js). An attacker could
create a malicious web page that, when viewed by a victim, could steal
arbitrary files (including private SSH keys, the /etc/passwd file, and
other potentially sensitive files) from the system running Firefox.
(CVE-2015-4495)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Cody Crews as the original reporter.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 38.1.1 ESR, which corrects this issue. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9da6f20"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021302.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5c07857"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d624f03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-38.1.1-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-38.1.1-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-38.1.1-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
