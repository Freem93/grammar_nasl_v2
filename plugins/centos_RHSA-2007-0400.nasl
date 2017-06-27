#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0400 and 
# CentOS Errata and Security Advisory 2007:0400 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36608);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_bugtraq_id(23082, 24242);
  script_osvdb_id(35134, 35135, 35136, 35137, 35138, 35139, 35140);
  script_xref(name:"RHSA", value:"2007:0400");

  script_name(english:"CentOS 4 / 5 : devhelp / firefox / yelp (CESA-2007:0400)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause Firefox to crash or potentially execute arbitrary
code as the user running Firefox. (CVE-2007-2867, CVE-2007-2868)

A flaw was found in the way Firefox handled certain FTP PASV commands.
A malicious FTP server could use this flaw to perform a rudimentary
port-scan of machines behind a user's firewall. (CVE-2007-1562)

Several denial of service flaws were found in the way Firefox handled
certain form and cookie data. A malicious website that is able to set
arbitrary form and cookie data could prevent Firefox from functioning
properly. (CVE-2007-1362, CVE-2007-2869)

A flaw was found in the way Firefox handled the addEventListener
JavaScript method. A malicious website could use this method to access
or modify sensitive data from another website. (CVE-2007-2870)

A flaw was found in the way Firefox displayed certain web content. A
malicious web page could generate content that would overlay user
interface elements such as the hostname and security indicators,
tricking users into thinking they are visiting a different site.
(CVE-2007-2871)

Users of Firefox are advised to upgrade to these erratum packages,
which contain Firefox version 1.5.0.12 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013854.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ad1ffe2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a6de5e5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e04bfd9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35523633"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e110cac2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a613ad04"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98dcfdaa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013842.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devhelp, firefox and / or yelp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-11.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-11.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
