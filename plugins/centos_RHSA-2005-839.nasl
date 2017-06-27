#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:839 and 
# CentOS Errata and Security Advisory 2005:839 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21872);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2929");
  script_bugtraq_id(15395);
  script_osvdb_id(20814);
  script_xref(name:"RHSA", value:"2005:839");

  script_name(english:"CentOS 3 / 4 : lynx (CESA-2005:839)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lynx package that corrects a security flaw is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Lynx is a text-based Web browser.

An arbitrary command execute bug was found in the lynx 'lynxcgi:' URI
handler. An attacker could create a web page redirecting to a
malicious URL which could execute arbitrary code as the user running
lynx. The Common Vulnerabilities and Exposures project assigned the
name CVE-2005-2929 to this issue.

Users should update to this erratum package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4c8c9d9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?071ab207"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fcdbac3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc596af7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fc6f5f4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?069039b1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/11");
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
if (rpm_check(release:"CentOS-3", reference:"lynx-2.8.5-11.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"lynx-2.8.5-18.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
