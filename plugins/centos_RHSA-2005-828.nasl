#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:828 and 
# CentOS Errata and Security Advisory 2005:828 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21869);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2974", "CVE-2005-3350");
  script_bugtraq_id(15299, 15304);
  script_osvdb_id(20470, 20471);
  script_xref(name:"RHSA", value:"2005:828");

  script_name(english:"CentOS 3 / 4 : libungif (CESA-2005:828)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libungif packages that fix two security issues are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libungif package contains a shared library of functions for
loading and saving GIF format image files.

Several bugs in the way libungif decodes GIF images were discovered.
An attacker could create a carefully crafted GIF image file in such a
way that it could cause an application linked with libungif to crash
or execute arbitrary code when the file is opened by a victim. The
Common Vulnerabilities and Exposures project has assigned the names
CVE-2005-2974 and CVE-2005-3350 to these issues.

All users of libungif are advised to upgrade to these updated
packages, which contain backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36d6223d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?444e1ff0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?571c4335"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1eb52c09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012387.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a25f4c53"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34c3b4fd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libungif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libungif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libungif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libungif-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/04");
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
if (rpm_check(release:"CentOS-3", reference:"libungif-4.1.0-15.el3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libungif-devel-4.1.0-15.el3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libungif-progs-4.1.0-15.el3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libungif-4.1.3-1.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libungif-devel-4.1.3-1.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libungif-progs-4.1.3-1.el4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
