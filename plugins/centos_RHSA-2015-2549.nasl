#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2549 and 
# CentOS Errata and Security Advisory 2015:2549 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87223);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710");
  script_osvdb_id(121175, 130292, 130435, 130535, 130536, 130538, 130539, 130543, 130641, 130642);
  script_xref(name:"RHSA", value:"2015:2549");

  script_name(english:"CentOS 6 : libxml2 (CESA-2015:2549)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

Several denial of service flaws were found in libxml2, a library
providing support for reading, modifying, and writing XML and HTML
files. A remote attacker could provide a specially crafted XML or HTML
file that, when processed by an application using libxml2, would cause
that application to use an excessive amount of CPU, leak potentially
sensitive information, or in certain cases crash the application.
(CVE-2015-5312, CVE-2015-7497, CVE-2015-7498, CVE-2015-7499,
CVE-2015-7500 CVE-2015-7941, CVE-2015-7942, CVE-2015-8241,
CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

Red Hat would like to thank the GNOME project for reporting
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, CVE-2015-7500,
CVE-2015-8241, CVE-2015-8242, and CVE-2015-8317. Upstream acknowledges
Kostya Serebryany of Google as the original reporter of CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, and CVE-2015-7500; Hugh Davenport as the
original reporter of CVE-2015-8241 and CVE-2015-8242; and Hanno Boeck
as the original reporter of CVE-2015-8317.

All libxml2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?192172d3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-20.el6_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
