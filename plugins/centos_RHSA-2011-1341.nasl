#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1341 and 
# CentOS Errata and Security Advisory 2011:1341 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56311);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000");
  script_osvdb_id(75834, 75837, 75838, 75839, 75841);
  script_xref(name:"RHSA", value:"2011:1341");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2011:1341)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-2995)

A flaw was found in the way Firefox processed the 'Enter' keypress
event. A malicious web page could present a download dialog while the
key is pressed, activating the default 'Open' action. A remote
attacker could exploit this vulnerability by causing the browser to
open malicious web content. (CVE-2011-2372)

A flaw was found in the way Firefox handled Location headers in
redirect responses. Two copies of this header with different values
could be a symptom of a CRLF injection attack against a vulnerable
server. Firefox now treats two copies of the Location, Content-Length,
or Content-Disposition header as an error condition. (CVE-2011-3000)

A flaw was found in the way Firefox handled frame objects with certain
names. An attacker could use this flaw to cause a plug-in to grant its
content access to another site or the local file system, violating the
same-origin policy. (CVE-2011-2999)

An integer underflow flaw was found in the way Firefox handled large
JavaScript regular expressions. A web page containing malicious
JavaScript could cause Firefox to access already freed memory, causing
Firefox to crash or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2011-2998)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.23. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.23, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69c7886c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04f9866f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93e431b5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99e75034"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.23-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.23-1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.23-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.23-1.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.23-1.el5_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
