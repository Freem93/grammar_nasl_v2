#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0766 and 
# CentOS Errata and Security Advisory 2015:0766 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82477);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2015-0801", "CVE-2015-0807", "CVE-2015-0813", "CVE-2015-0815", "CVE-2015-0816");
  script_osvdb_id(119753, 120077, 120078, 120079, 120090, 120101, 120106);
  script_xref(name:"RHSA", value:"2015:0766");

  script_name(english:"CentOS 5 / 6 / 7 : firefox / xulrunner (CESA-2015:0766)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-0813, CVE-2015-0815, CVE-2015-0801)

A flaw was found in the way documents were loaded via resource URLs
in, for example, Mozilla's PDF.js PDF file viewer. An attacker could
use this flaw to bypass certain restrictions and under certain
conditions even execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-0816)

A flaw was found in the Beacon interface implementation in Firefox. A
web page containing malicious content could allow a remote attacker to
conduct a Cross-Site Request Forgery (CSRF) attack. (CVE-2015-0807)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Byron Campen, Steve
Fink, Mariusz Mlynski, Christoph Kerschbaumer, Muneaki Nishimura, Olli
Pettay, Boris Zbarsky, and Aki Helin as the original reporters of
these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 31.6.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33b878f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?278ebc9b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78451b8f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-March/021009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbdc27a3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-31.6.0-2.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-31.6.0-2.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-31.6.0-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-31.6.0-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xulrunner-devel-31.6.0-2.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
