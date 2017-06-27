#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1441 and 
# CentOS Errata and Security Advisory 2013:1441 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70501);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 10:43:06 $");

  script_cve_id("CVE-2012-2125", "CVE-2012-2126", "CVE-2013-4287");
  script_bugtraq_id(53174, 55680, 62281);
  script_osvdb_id(81444, 85809, 97163);
  script_xref(name:"RHSA", value:"2013:1441");

  script_name(english:"CentOS 6 : rubygems (CESA-2013:1441)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rubygems package that fixes three security issues is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

RubyGems is the Ruby standard for publishing and managing third-party
libraries.

It was found that RubyGems did not verify SSL connections. This could
lead to man-in-the-middle attacks. (CVE-2012-2126)

It was found that, when using RubyGems, the connection could be
redirected from HTTPS to HTTP. This could lead to a user believing
they are installing a gem via HTTPS, when the connection may have been
silently downgraded to HTTP. (CVE-2012-2125)

It was discovered that the rubygems API validated version strings
using an unsafe regular expression. An application making use of this
API to process a version string from an untrusted source could be
vulnerable to a denial of service attack through CPU exhaustion.
(CVE-2013-4287)

Red Hat would like to thank Rubygems upstream for reporting
CVE-2013-4287. Upstream acknowledges Damir Sharipov as the original
reporter.

All rubygems users are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-October/019977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b453d4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygems package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"rubygems-1.3.7-4.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
