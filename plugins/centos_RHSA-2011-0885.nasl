#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0885 and 
# CentOS Errata and Security Advisory 2011:0885 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55404);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377", "CVE-2011-2605");
  script_osvdb_id(73177, 73178, 73179, 73180, 73181, 73182, 73183, 73184, 73185, 73186, 73187, 73188, 74319);
  script_xref(name:"RHSA", value:"2011:0885");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2011:0885)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A flaw was found in the way Firefox handled malformed JPEG images. A
website containing a malicious JPEG image could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2011-2377)

Multiple dangling pointer flaws were found in Firefox. A web page
containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374,
CVE-2011-2375, CVE-2011-2376)

An integer overflow flaw was found in the way Firefox handled
JavaScript Array objects. A website containing malicious JavaScript
could cause Firefox to execute that JavaScript with the privileges of
the user running Firefox. (CVE-2011-2371)

A use-after-free flaw was found in the way Firefox handled malformed
JavaScript. A website containing malicious JavaScript could cause
Firefox to execute that JavaScript with the privileges of the user
running Firefox. (CVE-2011-2373)

It was found that Firefox could treat two separate cookies as
interchangeable if both were for the same domain name but one of those
domain names had a trailing '.' character. This violates the
same-origin policy and could possibly lead to data being leaked to the
wrong domain. (CVE-2011-2362)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.18. You can find a link to the
Mozilla advisories in the References section of this erratum.

This update also fixes the following bug :

* With previous versions of Firefox on Red Hat Enterprise Linux 5, the
'background-repeat' CSS (Cascading Style Sheets) property did not work
(such images were not displayed and repeated as expected). (BZ#698313)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.18, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11f84ffb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?818b3eb9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08ad6d13"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74c4f2a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/23");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.18-2.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.18-2.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.18-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.18-2.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.18-2.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
