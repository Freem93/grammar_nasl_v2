#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1438 and 
# CentOS Errata and Security Advisory 2011:1438 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56782);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3648");
  script_osvdb_id(76948);
  script_xref(name:"RHSA", value:"2011:1438");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2011:1438)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes one security issue is now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A cross-site scripting (XSS) flaw was found in the way Thunderbird
handled certain multibyte character sets. Malicious, remote content
could cause Thunderbird to run JavaScript code with the permissions of
different remote content. (CVE-2011-3648)

Note: This issue cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. It
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
resolves this issue. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a403febc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8bb6703"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b70658bd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24ba226e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/14");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-45.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-45.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-27.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
