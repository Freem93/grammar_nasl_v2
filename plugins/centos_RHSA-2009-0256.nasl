#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0256 and 
# CentOS Errata and Security Advisory 2009:0256 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35590);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_bugtraq_id(33598);
  script_osvdb_id(51925, 51926, 51927, 51928, 51929, 51930, 51931, 51932, 51933, 51934, 51935, 51936, 51937, 51938, 51939, 51940);
  script_xref(name:"RHSA", value:"2009:0256");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2009:0256)");
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
(CVE-2009-0352, CVE-2009-0353, CVE-2009-0356)

Several flaws were found in the way malformed content was processed. A
website containing specially crafted content could, potentially, trick
a Firefox user into surrendering sensitive information.
(CVE-2009-0354, CVE-2009-0355)

A flaw was found in the way Firefox treated HTTPOnly cookies. An
attacker able to execute arbitrary JavaScript on a target site using
HTTPOnly cookies may be able to use this flaw to steal the cookie.
(CVE-2009-0357)

A flaw was found in the way Firefox treated certain HTTP page caching
directives. A local attacker could steal the contents of sensitive
pages which the page author did not intend to be cached.
(CVE-2009-0358)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.6. You can find a link to the
Mozilla advisories in the References section.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.6, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e3f42d4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d909409d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015607.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f54764c8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb54ba5a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4c60aec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-3.0.6-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss-3.12.2.0-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss-devel-3.12.2.0-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss-tools-3.12.2.0-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.6-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.2.0-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.2.0-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.2.0-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.2.0-4.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.6-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
