#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1088 and 
# CentOS Errata and Security Advisory 2012:1088 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59998);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_osvdb_id(83995, 83996, 83997, 83998, 83999, 84000, 84001, 84002, 84003, 84004, 84005, 84007, 84008, 84009, 84011, 84012, 84013);
  script_xref(name:"RHSA", value:"2012:1088");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2012:1088)");
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

A web page containing malicious content could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-1948, CVE-2012-1951, CVE-2012-1952,
CVE-2012-1953, CVE-2012-1954, CVE-2012-1958, CVE-2012-1962,
CVE-2012-1967)

A malicious web page could bypass same-compartment security wrappers
(SCSW) and execute arbitrary code with chrome privileges.
(CVE-2012-1959)

A flaw in the context menu functionality in Firefox could allow a
malicious website to bypass intended restrictions and allow a
cross-site scripting attack. (CVE-2012-1966)

A page different to that in the address bar could be displayed when
dragging and dropping to the address bar, possibly making it easier
for a malicious site or user to perform a phishing attack.
(CVE-2012-1950)

A flaw in the way Firefox called history.forward and history.back
could allow an attacker to conceal a malicious URL, possibly tricking
a user into believing they are viewing a trusted site. (CVE-2012-1955)

A flaw in a parser utility class used by Firefox to parse feeds (such
as RSS) could allow an attacker to execute arbitrary JavaScript with
the privileges of the user running Firefox. This issue could have
affected other browser components or add-ons that assume the class
returns sanitized input. (CVE-2012-1957)

A flaw in the way Firefox handled X-Frame-Options headers could allow
a malicious website to perform a clickjacking attack. (CVE-2012-1961)

A flaw in the way Content Security Policy (CSP) reports were generated
by Firefox could allow a malicious web page to steal a victim's OAuth
2.0 access tokens and OpenID credentials. (CVE-2012-1963)

A flaw in the way Firefox handled certificate warnings could allow a
man-in-the-middle attacker to create a crafted warning, possibly
tricking a user into accepting an arbitrary certificate as trusted.
(CVE-2012-1964)

A flaw in the way Firefox handled feed:javascript URLs could allow
output filtering to be bypassed, possibly leading to a cross-site
scripting attack. (CVE-2012-1965)

The nss update RHBA-2012:0337 for Red Hat Enterprise Linux 5 and 6
introduced a mitigation for the CVE-2011-3389 flaw. For compatibility
reasons, it remains disabled by default in the nss packages. This
update makes Firefox enable the mitigation by default. It can be
disabled by setting the NSS_SSL_CBC_RANDOM_IV environment variable to
0 before launching Firefox. (BZ#838879)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.6 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Benoit Jacob, Jesse Ruderman, Christian
Holler, Bill McCloskey, Abhishek Arya, Arthur Gerkis, Bill Keese,
moz_bug_r_a4, Bobby Holley, Code Audit Labs, Mariusz Mlynski, Mario
Heiderich, Frederic Buclin, Karthikeyan Bhargavan, Matt McCutchen,
Mario Gomes, and Soroush Dalili as the original reporters of these
issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.6 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?caff649a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27c55fed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.6-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.6-2.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.6-2.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.6-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.6-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.6-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
