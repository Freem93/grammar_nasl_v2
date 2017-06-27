#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:785 and 
# CentOS Errata and Security Advisory 2005:785 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21963);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2968", "CVE-2005-3089");
  script_osvdb_id(19589, 19643, 19644, 19645, 19646, 19647, 19648, 19649);
  script_xref(name:"RHSA", value:"2005:785");

  script_name(english:"CentOS 4 : firefox (CESA-2005:785)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes several security bugs is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

A bug was found in the way Firefox processes XBM image files. If a
user views a specially crafted XBM file, it becomes possible to
execute arbitrary code as the user running Firefox. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2701 to this issue.

A bug was found in the way Firefox processes certain Unicode
sequences. It may be possible to execute arbitrary code as the user
running Firefox if the user views a specially crafted Unicode
sequence. (CVE-2005-2702)

A bug was found in the way Firefox makes XMLHttp requests. It is
possible that a malicious web page could leverage this flaw to exploit
other proxy or server flaws from the victim's machine. It is also
possible that this flaw could be leveraged to send XMLHttp requests to
hosts other than the originator; the default behavior of the browser
is to disallow this. (CVE-2005-2703)

A bug was found in the way Firefox implemented its XBL interface. It
may be possible for a malicious web page to create an XBL binding in
such a way that would allow arbitrary JavaScript execution with chrome
permissions. Please note that in Firefox 1.0.6 this issue is not
directly exploitable and will need to leverage other unknown exploits.
(CVE-2005-2704)

An integer overflow bug was found in Firefox's JavaScript engine.
Under favorable conditions, it may be possible for a malicious web
page to execute arbitrary code as the user running Firefox.
(CVE-2005-2705)

A bug was found in the way Firefox displays about: pages. It is
possible for a malicious web page to open an about: page, such as
about:mozilla, in such a way that it becomes possible to execute
JavaScript with chrome privileges. (CVE-2005-2706)

A bug was found in the way Firefox opens new windows. It is possible
for a malicious website to construct a new window without any user
interface components, such as the address bar and the status bar. This
window could then be used to mislead the user for malicious purposes.
(CVE-2005-2707)

A bug was found in the way Firefox processes URLs passed to it on the
command line. If a user passes a malformed URL to Firefox, such as
clicking on a link in an instant messaging program, it is possible to
execute arbitrary commands as the user running Firefox.
(CVE-2005-2968)

Users of Firefox are advised to upgrade to this updated package that
contains Firefox version 1.0.7 and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8f52c11"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb7621d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?885a6299"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.0.7-1.4.1.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
