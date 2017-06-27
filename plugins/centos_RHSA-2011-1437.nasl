#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1437 and 
# CentOS Errata and Security Advisory 2011:1437 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56781);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_osvdb_id(76947, 76948, 76952);
  script_xref(name:"RHSA", value:"2011:1437");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2011:1437)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A flaw was found in the way Firefox handled certain add-ons. A web
page containing malicious content could cause an add-on to grant
itself full browser privileges, which could lead to arbitrary code
execution with the privileges of the user running Firefox.
(CVE-2011-3647)

A cross-site scripting (XSS) flaw was found in the way Firefox handled
certain multibyte character sets. A web page containing malicious
content could cause Firefox to run JavaScript code with the
permissions of a different website. (CVE-2011-3648)

A flaw was found in the way Firefox handled large JavaScript scripts.
A web page containing malicious JavaScript could cause Firefox to
crash or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2011-3650)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.24. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.24, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8dbacf1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e1c0312"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b1bc863"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018188.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44b5fda6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/14");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.24-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.24-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.24-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.24-2.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.24-2.el5_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
