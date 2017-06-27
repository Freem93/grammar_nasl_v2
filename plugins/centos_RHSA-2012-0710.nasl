#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0710 and 
# CentOS Errata and Security Advisory 2012:0710 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59388);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-3101", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");
  script_bugtraq_id(53791, 53792, 53793, 53794, 53796, 53797, 53799, 53800, 53801, 53808);
  script_osvdb_id(81963, 82665, 82666, 82667, 82669, 82672, 82673, 82674, 82676, 82677);
  script_xref(name:"RHSA", value:"2012:0710");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2012:0710)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-3101, CVE-2012-1937, CVE-2012-1938,
CVE-2012-1939, CVE-2012-1940, CVE-2012-1941, CVE-2012-1946,
CVE-2012-1947)

Note: CVE-2011-3101 only affected users of certain NVIDIA display
drivers with graphics cards that have hardware acceleration enabled.

It was found that the Content Security Policy (CSP) implementation in
Firefox no longer blocked Firefox inline event handlers. A remote
attacker could use this flaw to possibly bypass a web application's
intended restrictions, if that application relied on CSP to protect
against flaws such as cross-site scripting (XSS). (CVE-2012-1944)

If a web server hosted HTML files that are stored on a Microsoft
Windows share, or a Samba share, loading such files with Firefox could
result in Windows shortcut files (.lnk) in the same share also being
loaded. An attacker could use this flaw to view the contents of local
files and directories on the victim's system. This issue also affected
users opening HTML files from Microsoft Windows shares, or Samba
shares, that are mounted on their systems. (CVE-2012-1945)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.5 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Ken Russell of Google as the original
reporter of CVE-2011-3101; Igor Bukanov, Olli Pettay, Boris Zbarsky,
and Jesse Ruderman as the original reporters of CVE-2012-1937; Jesse
Ruderman, Igor Bukanov, Bill McCloskey, Christian Holler, Andrew
McCreight, and Brian Bondy as the original reporters of CVE-2012-1938;
Christian Holler as the original reporter of CVE-2012-1939; security
researcher Abhishek Arya of Google as the original reporter of
CVE-2012-1940, CVE-2012-1941, and CVE-2012-1947; security researcher
Arthur Gerkis as the original reporter of CVE-2012-1946; security
researcher Adam Barth as the original reporter of CVE-2012-1944; and
security researcher Paul Stone as the original reporter of
CVE-2012-1945.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.5 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac3e18ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2caa93f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.5-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.5-1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.5-1.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.5-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.5-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.5-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
