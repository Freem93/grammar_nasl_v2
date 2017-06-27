#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1823 and 
# CentOS Errata and Security Advisory 2013:1823 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71357);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-0772", "CVE-2013-5609", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-6671", "CVE-2013-6674");
  script_bugtraq_id(58034, 64203, 64204, 64205, 64207, 64209, 64211, 64212);
  script_osvdb_id(90427, 100807, 100810, 100811, 100812, 100813, 100815, 100816);
  script_xref(name:"RHSA", value:"2013:1823");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2013:1823)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2013-5609, CVE-2013-5616, CVE-2013-5618,
CVE-2013-6671, CVE-2013-5613)

A flaw was found in the way Thunderbird rendered web content with
missing character encoding information. An attacker could use this
flaw to possibly bypass same-origin inheritance and perform cross
site-scripting (XSS) attacks. (CVE-2013-5612)

It was found that certain malicious web content could bypass
restrictions applied by sandboxed iframes. An attacker could combine
this flaw with other vulnerabilities to execute arbitrary code with
the privileges of the user running Thunderbird. (CVE-2013-5614)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message as JavaScript is disabled by default for
mail messages. They could be exploited another way in Thunderbird, for
example, when viewing the full remote content of an RSS feed.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Ben Turner, Bobby Holley, Jesse
Ruderman, Christian Holler, Masato Kinugawa, Daniel Veditz, Jesse
Schwartzentruber, Nils, Tyson Smith, and Atte Kettunen as the original
reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 24.2.0 ESR. You can find a link to
the Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 24.2.0 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4748dad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020072.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bfedb97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-24.2.0-2.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-24.2.0-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
