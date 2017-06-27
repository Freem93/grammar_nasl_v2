#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0500 and 
# CentOS Errata and Security Advisory 2010:0500 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48265);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2008-5913", "CVE-2009-5017", "CVE-2010-0182", "CVE-2010-0183", "CVE-2010-1028", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-3171");
  script_osvdb_id(53341, 62416, 63457, 63479, 65734, 65735, 65739, 65742, 65744, 65749, 65750, 65751, 65752);
  script_xref(name:"RHSA", value:"2010:0500");

  script_name(english:"CentOS 4 : firefox (CESA-2010:0500)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that addresses security issues, fixes bugs,
adds numerous enhancements, and upgrades Firefox to version 3.6.4, is
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-1121, CVE-2010-1200, CVE-2010-1202,
CVE-2010-1203)

A flaw was found in the way browser plug-ins interact. It was possible
for a plug-in to reference the freed memory from a different plug-in,
resulting in the execution of arbitrary code with the privileges of
the user running Firefox. (CVE-2010-1198)

Several integer overflow flaws were found in the processing of
malformed web content. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2010-1196,
CVE-2010-1199)

A focus stealing flaw was found in the way Firefox handled focus
changes. A malicious website could use this flaw to steal sensitive
data from a user, such as usernames and passwords. (CVE-2010-1125)

A flaw was found in the way Firefox handled the 'Content-Disposition:
attachment' HTTP header when the 'Content-Type: multipart' HTTP header
was also present. A website that allows arbitrary uploads and relies
on the 'Content-Disposition: attachment' HTTP header to prevent
content from being displayed inline, could be used by an attacker to
serve malicious content to users. (CVE-2010-1197)

A flaw was found in the Firefox Math.random() function. This function
could be used to identify a browsing session and track a user across
different websites. (CVE-2008-5913)

A flaw was found in the Firefox XML document loading security checks.
Certain security checks were not being called when an XML document was
loaded. This could possibly be leveraged later by an attacker to load
certain resources that violate the security policies of the browser or
its add-ons. Note that this issue cannot be exploited by only loading
an XML document. (CVE-2010-0182)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.4. You can find a link to the
Mozilla advisories in the References section of this erratum.

This erratum upgrades Firefox from version 3.0.19 to version 3.6.4,
and as such, contains multiple bug fixes and numerous enhancements.
Space precludes documenting these changes in this advisory. For
details concerning these changes, refer to the Firefox Release Notes
links in the References section of this erratum.

Important: Firefox 3.6.4 is not completely backwards-compatible with
all Mozilla Add-ons and Firefox plug-ins that worked with Firefox
3.0.19. Firefox 3.6 checks compatibility on first-launch, and,
depending on the individual configuration and the installed Add-ons
and plug-ins, may disable said Add-ons and plug-ins, or attempt to
check for updates and upgrade them. Add-ons and plug-ins may have to
be manually updated.

All Firefox users should upgrade to this updated package, which
contains Firefox version 3.6.4. After installing the update, Firefox
must be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f95a7081"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8468b0d1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.4-8.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.4-8.el4.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
