#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1852 and 
# CentOS Errata and Security Advisory 2015:1852 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(86482);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:15:06 $");

  script_cve_id("CVE-2015-4500", "CVE-2015-4509", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_osvdb_id(127875, 127876, 127877, 127878, 127879, 127880, 127881, 127882, 127892, 127915, 127916, 127917, 127918, 127919, 127920, 127921, 127922, 127923, 127924);
  script_xref(name:"RHSA", value:"2015:1852");

  script_name(english:"CentOS 5 / 6 / 7 : thunderbird (CESA-2015:1852)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2015-4500, CVE-2015-4509,
CVE-2015-4517, CVE-2015-4521, CVE-2015-4522, CVE-2015-7174,
CVE-2015-7175, CVE-2015-7176, CVE-2015-7177, CVE-2015-7180)

Two information leak flaws were found in the processing of malformed
web content. A web page containing malicious content could cause
Thunderbird to disclose sensitive information or, in certain cases,
crash. (CVE-2015-4519, CVE-2015-4520)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message because JavaScript is disabled by default
for mail messages. However, they could be exploited in other ways in
Thunderbird (for example, by viewing the full remote content of an RSS
feed).

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Andrew Osmond, Olli Pettay, Andrew
Sutherland, Christian Holler, David Major, Andrew McCreight, Cameron
McCormack, Ronald Crane, Mario Gomes, and Ehsan Akhgari as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 38.3.0 You can find a link to the
Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.3.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eba5390d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cfca162"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c70bebf4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-38.3.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-38.3.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-38.3.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
