#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0207 and 
# CentOS Errata and Security Advisory 2008:0207 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31684);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_osvdb_id(42601, 43846, 43847, 43848, 43849, 43857, 43858, 43859, 43860, 43861, 43862, 43863, 43864, 43865, 43866, 43867, 43868, 43869, 43870, 43871, 43872, 43873, 43874, 43875, 43876, 43877, 43878);
  script_xref(name:"RHSA", value:"2008:0207");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2008:0207)");
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

Several flaws were found in the processing of some malformed web
content. A web page containing such malicious content could cause
Firefox to crash or, potentially, execute arbitrary code as the user
running Firefox. (CVE-2008-1233, CVE-2008-1235, CVE-2008-1236,
CVE-2008-1237)

Several flaws were found in the display of malformed web content. A
web page containing specially crafted content could, potentially,
trick a Firefox user into surrendering sensitive information.
(CVE-2008-1234, CVE-2008-1238, CVE-2008-1241)

All Firefox users should upgrade to these updated packages, which
contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ea1693b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014779.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18c6153b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b804c82"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6307f056"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb60aa66"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.14.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-14.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-14.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
