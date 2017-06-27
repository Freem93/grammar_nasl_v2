#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0879 and 
# CentOS Errata and Security Advisory 2008:0879 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43709);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068");
  script_bugtraq_id(31346);
  script_xref(name:"RHSA", value:"2008:0879");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2008:0879)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes various security issues is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-4058, CVE-2008-4060, CVE-2008-4061, CVE-2008-4062,
CVE-2008-4063, CVE-2008-4064)

Several flaws were found in the way malformed web content was
displayed. A web page containing specially crafted content could
potentially trick a Firefox user into surrendering sensitive
information. (CVE-2008-4067, CVE-2008-4068)

A flaw was found in the way Firefox handles mouse click events. A web
page containing specially crafted JavaScript code could move the
content window while a mouse-button was pressed, causing any item
under the pointer to be dragged. This could, potentially, cause the
user to perform an unsafe drag-and-drop action. (CVE-2008-3837)

A flaw was found in Firefox that caused certain characters to be
stripped from JavaScript code. This flaw could allow malicious
JavaScript to bypass or evade script filters. (CVE-2008-4065)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.2. You can find a link to the
Mozilla advisories in the References section.

All firefox users should upgrade to this updated package, which
contains backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7816fe97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d7e8ceb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6db676ec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f42b4d3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f1bc754"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.10-0.10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.10-0.10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.10-0.10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.10.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"firefox-3.0.2-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-19.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-19.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.2-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.1.1-1.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.1.1-1.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.1.1-1.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.1.1-1.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.2-5.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.2-5.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.2-5.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
