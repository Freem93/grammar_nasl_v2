#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0112 and 
# CentOS Errata and Security Advisory 2010:0112 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44648);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162", "CVE-2010-0167", "CVE-2010-0169", "CVE-2010-0171");
  script_bugtraq_id(38285, 38286, 38287, 38288, 38289);
  script_osvdb_id(62425, 62426, 62427, 62428);
  script_xref(name:"RHSA", value:"2010:0112");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2010:0112)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A use-after-free flaw was found in Firefox. Under low memory
conditions, visiting a web page containing malicious content could
result in Firefox executing arbitrary code with the privileges of the
user running Firefox. (CVE-2009-1571)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-0159, CVE-2010-0160)

Two flaws were found in the way certain content was processed. An
attacker could use these flaws to create a malicious web page that
could bypass the same-origin policy, or possibly run untrusted
JavaScript. (CVE-2009-3988, CVE-2010-0162)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.0.18. You can find a link to the
Mozilla advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.18, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a6b23d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8e078b0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016525.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51cd80cf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8954eca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 94, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/18");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.0.18-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.0.18-1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.18-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.18-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.18-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.18-1.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");