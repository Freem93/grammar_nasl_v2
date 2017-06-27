#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1164 and 
# CentOS Errata and Security Advisory 2011:1164 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55862);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");
  script_bugtraq_id(49166);
  script_osvdb_id(74581, 74582, 74584, 74585, 74586, 74587);
  script_xref(name:"RHSA", value:"2011:1164");

  script_name(english:"CentOS 4 / 5 : firefox / xulrunner (CESA-2011:1164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-2982)

A dangling pointer flaw was found in the Firefox Scalable Vector
Graphics (SVG) text manipulation routine. A web page containing a
malicious SVG image could cause Firefox to crash or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2011-0084)

A dangling pointer flaw was found in the way Firefox handled a certain
Document Object Model (DOM) element. A web page containing malicious
content could cause Firefox to crash or, potentially, execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2011-2378)

A flaw was found in the event management code in Firefox. A website
containing malicious JavaScript could cause Firefox to execute that
JavaScript with the privileges of the user running Firefox.
(CVE-2011-2981)

A flaw was found in the way Firefox handled malformed JavaScript. A
web page containing malicious JavaScript could cause Firefox to access
already freed memory, causing Firefox to crash or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2011-2983)

It was found that a malicious web page could execute arbitrary code
with the privileges of the user running Firefox if the user dropped a
tab onto the malicious web page. (CVE-2011-2984)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.20. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.20, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e81f521e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d12ee86"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a670e7a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4ba008a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?695bc3ad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e55e5c5"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?922d50df"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1009f19"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37b2b964"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?882ffd99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.20-2.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.20-2.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.20-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.20-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.20-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
