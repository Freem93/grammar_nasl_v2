#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0573 and 
# CentOS Errata and Security Advisory 2006:0573 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21906);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_osvdb_id(26939, 26940, 26941, 26942, 26943, 26944, 26945);
  script_xref(name:"RHSA", value:"2006:0573");

  script_name(english:"CentOS 3 / 4 : openoffice.org (CESA-2006:0573)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

A Sun security specialist reported an issue with the application
framework. An attacker could put macros into document locations that
could cause OpenOffice.org to execute them when the file was opened by
a victim. (CVE-2006-2198)

A bug was found in the OpenOffice.org Java virtual machine
implementation. An attacker could write a carefully crafted Java
applet that can break through the 'sandbox' and have full access to
system resources with the current user privileges. (CVE-2006-2199)

A buffer overflow bug was found in the OpenOffice.org file processor.
An attacker could create a carefully crafted XML file that could cause
OpenOffice.org to write data to an arbitrary location in memory when
the file was opened by a victim. (CVE-2006-3117)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported fixes for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/012989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d1fae3c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/012990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d09ec4e2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/012991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcff224b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/012992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d342df1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-1.1.2-34.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-1.1.2-34.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-34.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-34.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-34.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-34.2.0.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-kde-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-kde-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-libs-1.1.2-34.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-34.6.0.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
