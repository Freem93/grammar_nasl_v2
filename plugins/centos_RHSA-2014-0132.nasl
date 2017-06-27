#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0132 and 
# CentOS Errata and Security Advisory 2014:0132 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72350);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487");
  script_bugtraq_id(65317, 65320, 65326, 65328, 65330, 65334);
  script_osvdb_id(102863, 102864, 102866, 102868, 102872, 102873);
  script_xref(name:"RHSA", value:"2014:0132");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2014:0132)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
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
running Firefox. (CVE-2014-1477, CVE-2014-1482, CVE-2014-1486)

A flaw was found in the way Firefox handled error messages related to
web workers. An attacker could use this flaw to bypass the same-origin
policy, which could lead to cross-site scripting (XSS) attacks, or
could potentially be used to gather authentication tokens and other
data from third-party websites. (CVE-2014-1487)

A flaw was found in the implementation of System Only Wrappers (SOW).
An attacker could use this flaw to crash Firefox. When combined with
other vulnerabilities, this flaw could have additional security
implications. (CVE-2014-1479)

It was found that the Firefox JavaScript engine incorrectly handled
window objects. A remote attacker could use this flaw to bypass
certain security checks and possibly execute arbitrary code.
(CVE-2014-1481)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Terrence Cole, Jesse
Ruderman, Gary Kwong, Eric Rescorla, Jonathan Kew, Dan Gohman, Ryan
VanderMeulen, Sotaro Ikeda, Cody Crews, Fredrik 'Flonka' Lonnqvist,
Arthur Gerkis, Masato Kinugawa, and Boris Zbarsky as the original
reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 24.3.0 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 24.3.0 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cbbc8d8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f2af417"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-24.3.0-2.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-24.3.0-2.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
