#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0090 and 
# CentOS Errata and Security Advisory 2008:0090 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43673);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:21:02 $");

  script_cve_id("CVE-2007-4770", "CVE-2007-4771");
  script_bugtraq_id(27455);
  script_osvdb_id(41189, 41190);
  script_xref(name:"RHSA", value:"2008:0090");

  script_name(english:"CentOS 5 : icu (CESA-2008:0090)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated icu packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The International Components for Unicode (ICU) library provides robust
and full-featured Unicode services.

Will Drewry reported multiple flaws in the way libicu processed
certain malformed regular expressions. If an application linked
against ICU, such as OpenOffice.org, processed a carefully crafted
regular expression, it may be possible to execute arbitrary code as
the user running the application. (CVE-2007-4770, CVE-2007-4771)

All users of icu should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9edc014"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014655.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efa35ada"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libicu-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"icu-3.6-5.11.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-3.6-5.11.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-devel-3.6-5.11.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libicu-doc-3.6-5.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
