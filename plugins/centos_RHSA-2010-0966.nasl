#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0966 and 
# CentOS Errata and Security Advisory 2010:0966 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51777);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777");
  script_bugtraq_id(45314, 45322, 45324, 45326, 45352, 45354);
  script_osvdb_id(69776);
  script_xref(name:"RHSA", value:"2010:0966");

  script_name(english:"CentOS 4 : firefox (CESA-2010:0966)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
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

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-3766, CVE-2010-3767, CVE-2010-3772,
CVE-2010-3776, CVE-2010-3777)

A flaw was found in the way Firefox handled malformed JavaScript. A
website with an object containing malicious JavaScript could cause
Firefox to execute that JavaScript with the privileges of the user
running Firefox. (CVE-2010-3771)

This update adds support for the Sanitiser for OpenType (OTS) library
to Firefox. This library helps prevent potential exploits in malformed
OpenType fonts by verifying the font file prior to use.
(CVE-2010-3768)

A flaw was found in the way Firefox loaded Java LiveConnect scripts.
Malicious web content could load a Java LiveConnect script in a way
that would result in the plug-in object having elevated privileges,
allowing it to execute Java code with the privileges of the user
running Firefox. (CVE-2010-3775)

It was found that the fix for CVE-2010-0179 was incomplete when the
Firebug add-on was used. If a user visited a website containing
malicious JavaScript while the Firebug add-on was enabled, it could
cause Firefox to execute arbitrary JavaScript with the privileges of
the user running Firefox. (CVE-2010-3773)

A flaw was found in the way Firefox presented the location bar to
users. A malicious website could trick a user into thinking they are
visiting the site reported by the location bar, when the page is
actually content controlled by an attacker. (CVE-2010-3774)

A cross-site scripting (XSS) flaw was found in the Firefox
x-mac-arabic, x-mac-farsi, and x-mac-hebrew character encodings.
Certain characters were converted to angle brackets when displayed. If
server-side script filtering missed these cases, it could result in
Firefox executing JavaScript code with the permissions of a different
website. (CVE-2010-3770)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.13. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.13, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cbaaf23"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07ff809e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.13-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.13-3.el4.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
