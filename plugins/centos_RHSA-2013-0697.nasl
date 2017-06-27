#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0697 and 
# CentOS Errata and Security Advisory 2013:0697 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65771);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800");
  script_bugtraq_id(58818);
  script_xref(name:"RHSA", value:"2013:0697");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2013:0697)");
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
Thunderbird. (CVE-2013-0788)

A flaw was found in the way Same Origin Wrappers were implemented in
Thunderbird. Malicious content could use this flaw to bypass the
same-origin policy and execute arbitrary code with the privileges of
the user running Thunderbird. (CVE-2013-0795)

A flaw was found in the embedded WebGL library in Thunderbird.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. Note: This issue only affected systems using the Intel
Mesa graphics drivers. (CVE-2013-0796)

An out-of-bounds write flaw was found in the embedded Cairo library in
Thunderbird. Malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2013-0800)

A flaw was found in the way Thunderbird handled the JavaScript history
functions. Malicious content could cause a page to be displayed that
has a baseURI pointing to a different site, allowing cross-site
scripting (XSS) and phishing attacks. (CVE-2013-0793)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Olli Pettay, Jesse Ruderman, Boris
Zbarsky, Christian Holler, Milan Sreckovic, Joe Drew, Cody Crews,
miaubiz, Abhishek Arya, and Mariusz Mlynski as the original reporters
of these issues.

Note: All issues except CVE-2013-0800 cannot be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 17.0.5 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18cfd01b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82a2d068"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-17.0.5-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-17.0.5-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
