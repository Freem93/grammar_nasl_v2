#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2580 and 
# CentOS Errata and Security Advisory 2016:2580 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95327);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/28 15:05:43 $");

  script_cve_id("CVE-2015-8868");
  script_osvdb_id(132203);
  script_xref(name:"RHSA", value:"2016:2580");

  script_name(english:"CentOS 7 : poppler (CESA-2016:2580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for poppler is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Security Fix(es) :

* A heap-buffer overflow was found in the poppler library. An attacker
could create a malicious PDF file that would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code when opened. (CVE-2015-8868)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003430.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a4c1251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-demos-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-devel-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-16.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-utils-0.26.5-16.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
