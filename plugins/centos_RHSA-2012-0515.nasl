#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0515 and 
# CentOS Errata and Security Advisory 2012:0515 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58850);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_bugtraq_id(53218, 53219, 53220, 53221, 53222, 53223, 53224, 53225, 53227, 53228, 53229, 53231);
  script_osvdb_id(80740, 81513, 81514, 81515, 81516, 81517, 81518, 81519, 81520, 81522, 81523, 81524);
  script_xref(name:"RHSA", value:"2012:0515");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2012:0515)");
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

A flaw was found in Sanitiser for OpenType (OTS), used by Firefox to
help prevent potential exploits in malformed OpenType fonts. A web
page containing malicious content could cause Firefox to crash or,
under certain conditions, possibly execute arbitrary code with the
privileges of the user running Firefox. (CVE-2011-3062)

A web page containing malicious content could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-0467, CVE-2012-0468, CVE-2012-0469)

A web page containing a malicious Scalable Vector Graphics (SVG) image
file could cause Firefox to crash or, potentially, execute arbitrary
code with the privileges of the user running Firefox. (CVE-2012-0470)

A flaw was found in the way Firefox used its embedded Cairo library to
render certain fonts. A web page containing malicious content could
cause Firefox to crash or, under certain conditions, possibly execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2012-0472)

A flaw was found in the way Firefox rendered certain images using
WebGL. A web page containing malicious content could cause Firefox to
crash or, under certain conditions, possibly execute arbitrary code
with the privileges of the user running Firefox. (CVE-2012-0478)

A cross-site scripting (XSS) flaw was found in the way Firefox handled
certain multibyte character sets. A web page containing malicious
content could cause Firefox to run JavaScript code with the
permissions of a different website. (CVE-2012-0471)

A flaw was found in the way Firefox rendered certain graphics using
WebGL. A web page containing malicious content could cause Firefox to
crash. (CVE-2012-0473)

A flaw in Firefox allowed the address bar to display a different
website than the one the user was visiting. An attacker could use this
flaw to conceal a malicious URL, possibly tricking a user into
believing they are viewing a trusted site, or allowing scripts to be
loaded from the attacker's site, possibly leading to cross-site
scripting (XSS) attacks. (CVE-2012-0474)

A flaw was found in the way Firefox decoded the ISO-2022-KR and
ISO-2022-CN character sets. A web page containing malicious content
could cause Firefox to run JavaScript code with the permissions of a
different website. (CVE-2012-0477)

A flaw was found in the way Firefox handled RSS and Atom feeds.
Invalid RSS or Atom content loaded over HTTPS caused Firefox to
display the address of said content in the location bar, but not the
content in the main window. The previous content continued to be
displayed. An attacker could use this flaw to perform phishing
attacks, or trick users into thinking they are visiting the site
reported by the location bar, when the page is actually content
controlled by an attacker. (CVE-2012-0479)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.4 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Mateusz Jurczyk of the Google Security
Team as the original reporter of CVE-2011-3062; Aki Helin from OUSPG
as the original reporter of CVE-2012-0469; Atte Kettunen from OUSPG as
the original reporter of CVE-2012-0470; wushi of team509 via iDefense
as the original reporter of CVE-2012-0472; Ms2ger as the original
reporter of CVE-2012-0478; Anne van Kesteren of Opera Software as the
original reporter of CVE-2012-0471; Matias Juntunen as the original
reporter of CVE-2012-0473; Jordi Chancel and Eddy Bordi, and Chris
McGowen as the original reporters of CVE-2012-0474; Masato Kinugawa as
the original reporter of CVE-2012-0477; and Jeroen van der Gun as the
original reporter of CVE-2012-0479."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10571886"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2e6ab82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.4-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.4-1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.4-1.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.4-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.4-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.4-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
