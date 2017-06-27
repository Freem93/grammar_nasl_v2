#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0597 and 
# CentOS Errata and Security Advisory 2008:0597 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43699);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
  script_bugtraq_id(29802, 30242);
  script_osvdb_id(47465);
  script_xref(name:"RHSA", value:"2008:0597");

  script_name(english:"CentOS 5 : firefox (CESA-2008:0597)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix various security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 16th July 2008] The nspluginwrapper package has been added to
this advisory to satisfy a missing package dependency issue.

Mozilla Firefox is an open source Web browser.

An integer overflow flaw was found in the way Firefox displayed
certain web content. A malicious website could cause Firefox to crash,
or execute arbitrary code with the permissions of the user running
Firefox. (CVE-2008-2785)

A flaw was found in the way Firefox handled certain command line URLs.
If another application passed Firefox a malformed URL, it could result
in Firefox executing local malicious content with chrome privileges.
(CVE-2008-2933)

All firefox users should upgrade to these updated packages, which
contain Firefox 3.0.1 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14d3f09b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0b083e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-18.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-18.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.1-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.1-1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.1-1.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.1-1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
