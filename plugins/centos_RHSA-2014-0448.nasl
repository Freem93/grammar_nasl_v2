#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0448 and 
# CentOS Errata and Security Advisory 2014:0448 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73790);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(67123, 67129, 67130, 67131, 67134, 67135, 67137);
  script_osvdb_id(106397);
  script_xref(name:"RHSA", value:"2014:0448");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2014:0448)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes several security issues is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2014-1518, CVE-2014-1524, CVE-2014-1529,
CVE-2014-1531)

A use-after-free flaw was found in the way Firefox resolved hosts in
certain circumstances. An attacker could use this flaw to crash
Firefox or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2014-1532)

An out-of-bounds read flaw was found in the way Firefox decoded JPEG
images. Loading a web page containing a specially crafted JPEG image
could cause Firefox to crash. (CVE-2014-1523)

A flaw was found in the way Firefox handled browser navigations
through history. An attacker could possibly use this flaw to cause the
address bar of the browser to display a web page name while loading
content from an entirely different web page, which could allow for
cross-site scripting (XSS) attacks. (CVE-2014-1530)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Bobby Holley, Carsten Book, Christoph
Diehl, Gary Kwong, Jan de Mooij, Jesse Ruderman, Nathan Froyd,
Christian Holler, Abhishek Arya, Mariusz Mlynski, moz_bug_r_a4, Nils,
Tyson Smith, and Jesse Schwartzentrube as the original reporters of
these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 24.5.0 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to this updated package, which
contains Firefox version 24.5.0 ESR, which corrects these issues.
After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3190cf34"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aa352fb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/01");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-24.5.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-24.5.0-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
