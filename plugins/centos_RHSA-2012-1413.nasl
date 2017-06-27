#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1413 and 
# CentOS Errata and Security Advisory 2012:1413 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62763);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_osvdb_id(86773, 86774, 86775);
  script_xref(name:"RHSA", value:"2012:1413");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2012:1413)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Multiple flaws were found in the location object implementation in
Thunderbird. Malicious content could be used to perform cross-site
scripting attacks, bypass the same-origin policy, or cause Thunderbird
to execute arbitrary code. (CVE-2012-4194, CVE-2012-4195,
CVE-2012-4196)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Mariusz Mlynski, moz_bug_r_a4, and
Antoine Delignat-Lavaud as the original reporters of these issues.

Note: None of the issues in this advisory can be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.10 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c0c6b81"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0dac62d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-10.0.10-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-10.0.10-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
