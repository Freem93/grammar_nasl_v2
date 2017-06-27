#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0718 and 
# CentOS Errata and Security Advisory 2015:0718 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82083);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:59:33 $");

  script_cve_id("CVE-2015-0817", "CVE-2015-0818");
  script_xref(name:"RHSA", value:"2015:0718");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2015:0718)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix two security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Two flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-0817, CVE-2015-0818)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges ilxu1a and Mariusz Mlynski as the
original reporters of these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 31.5.3 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80d4cb34"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-March/020994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c915241"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-March/020996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a1ee562"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-March/001860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?241458af"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-31.5.3-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-31.5.3-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-31.5.3-3.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
