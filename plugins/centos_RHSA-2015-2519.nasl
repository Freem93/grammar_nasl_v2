#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2519 and 
# CentOS Errata and Security Advisory 2015:2519 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87067);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-4513", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_osvdb_id(129763, 129764, 129765, 129766, 129767, 129768, 129769, 129770, 129771, 129772, 129773, 129783, 129784, 129785, 129790, 129791, 129800);
  script_xref(name:"RHSA", value:"2015:2519");

  script_name(english:"CentOS 5 / 6 / 7 : thunderbird (CESA-2015:2519)");
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
user running Thunderbird. (CVE-2015-4513, CVE-2015-7189,
CVE-2015-7197, CVE-2015-7198, CVE-2015-7199, CVE-2015-7200)

A same-origin policy bypass flaw was found in the way Thunderbird
handled certain cross-origin resource sharing (CORS) requests. A web
page containing malicious content could cause Thunderbird to disclose
sensitive information. (CVE-2015-7193)

Note: All of the above issues cannot be exploited by a specially
crafted HTML mail message because JavaScript is disabled by default
for mail messages. However, they could be exploited in other ways in
Thunderbird (for example, by viewing the full remote content of an RSS
feed).

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Christian Holler, David Major, Jesse
Ruderman, Tyson Smith, Boris Zbarsky, Randell Jesup, Olli Pettay, Karl
Tomlinson, Jeff Walden, Gary Kwong, Looben Yang, Shinto K Anto, Ronald
Crane, and Ehsan Akhgari as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Thunderbird 38.4.0. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.4.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-November/021509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30c3996f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-November/021510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?088d8e77"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-December/002724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?059f881b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-38.4.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-38.4.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-38.4.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
