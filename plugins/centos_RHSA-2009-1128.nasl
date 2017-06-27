#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1128 and 
# CentOS Errata and Security Advisory 2009:1128 respectively.
#

include("compat.inc");

if (description)
{
  script_id(39524);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-1698");
  script_bugtraq_id(35318);
  script_xref(name:"RHSA", value:"2009:1128");

  script_name(english:"CentOS 3 : kdelibs (CESA-2009:1128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix one security issue are now available
for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdelibs packages provide libraries for the K Desktop Environment
(KDE).

A flaw was found in the way the KDE CSS parser handled content for the
CSS 'style' attribute. A remote attacker could create a specially
crafted CSS equipped HTML page, which once visited by an unsuspecting
user, could cause a denial of service (Konqueror crash) or,
potentially, execute arbitrary code with the privileges of the user
running Konqueror. (CVE-2009-1698)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The desktop must be restarted
(log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/016001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34c8478b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/016002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2094d2e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kdelibs-3.1.3-6.13")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kdelibs-3.1.3-6.13")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kdelibs-devel-3.1.3-6.13")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kdelibs-devel-3.1.3-6.13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
