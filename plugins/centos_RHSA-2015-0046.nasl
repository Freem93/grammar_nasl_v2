#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0046 and 
# CentOS Errata and Security Advisory 2015:0046 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80526);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-8634", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8641");
  script_bugtraq_id(72044, 72046, 72047, 72049);
  script_osvdb_id(116998, 117001, 117003, 117004, 117007);
  script_xref(name:"RHSA", value:"2015:0046");

  script_name(english:"CentOS 5 / 6 / 7 : firefox / xulrunner (CESA-2015:0046)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues and one bug
are now available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2014-8634, CVE-2014-8639, CVE-2014-8641)

It was found that the Beacon interface implementation in Firefox did
not follow the Cross-Origin Resource Sharing (CORS) specification. A
web page containing malicious content could allow a remote attacker to
conduct a Cross-Site Request Forgery (XSRF) attack. (CVE-2014-8638)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Patrick McManus,
Muneaki Nishimura, Xiaofeng Zheng, and Mitchell Harper as the original
reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 31.4.0 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

This update also fixes the following bug :

* The default dictionary for Firefox's spell checker is now correctly
set to the system's locale language. (BZ#643954, BZ#1150572)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 31.4.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf618d88"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?546c64e8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a99f4c9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b5aba2b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-31.4.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-31.4.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-31.4.0-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-31.4.0-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-devel-31.4.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
