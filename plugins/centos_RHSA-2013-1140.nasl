#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1140 and 
# CentOS Errata and Security Advisory 2013:1140 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69245);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2013-1701", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_xref(name:"RHSA", value:"2013:1140");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2013:1140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2013-1701)

A flaw was found in the way Firefox generated Certificate Request
Message Format (CRMF) requests. An attacker could use this flaw to
perform cross-site scripting (XSS) attacks or execute arbitrary code
with the privileges of the user running Firefox. (CVE-2013-1710)

A flaw was found in the way Firefox handled the interaction between
frames and browser history. An attacker could use this flaw to trick
Firefox into treating malicious content as if it came from the browser
history, allowing for XSS attacks. (CVE-2013-1709)

It was found that the same-origin policy could be bypassed due to the
way Uniform Resource Identifiers (URI) were checked in JavaScript. An
attacker could use this flaw to perform XSS attacks, or install
malicious add-ons from third-party pages. (CVE-2013-1713)

It was found that web workers could bypass the same-origin policy. An
attacker could use this flaw to perform XSS attacks. (CVE-2013-1714)

It was found that, in certain circumstances, Firefox incorrectly
handled Java applets. If a user launched an untrusted Java applet via
Firefox, the applet could use this flaw to obtain read-only access to
files on the user's local system. (CVE-2013-1717)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Jeff Gilbert, Henrik Skupin,
moz_bug_r_a4, Cody Crews, Federico Lanusse, and Georgi Guninski as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 17.0.8 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 17.0.8 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1384ac55"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee705521"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-17.0.8-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-17.0.8-3.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-17.0.8-3.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-17.0.8-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-17.0.8-3.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-17.0.8-3.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
