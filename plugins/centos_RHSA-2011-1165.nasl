#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1165 and 
# CentOS Errata and Security Advisory 2011:1165 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55863);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2011-2982", "CVE-2011-2983");
  script_bugtraq_id(49166);
  script_osvdb_id(74585, 74586);
  script_xref(name:"RHSA", value:"2011:1165");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2011:1165)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML content.
Malicious HTML content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2011-2982)

A flaw was found in the way Thunderbird handled malformed JavaScript.
Malicious content could cause Thunderbird to access already freed
memory, causing Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2011-2983)

Note: This update disables support for Scalable Vector Graphics (SVG)
images in Thunderbird on Red Hat Enterprise Linux 5.

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017696.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b310fa9b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f5f0e43"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa553762"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3909b8f1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000220.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aa605d1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2278d78e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-40.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-40.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-21.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
