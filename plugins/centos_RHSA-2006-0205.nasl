#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0205 and 
# CentOS Errata and Security Advisory 2006:0205 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21985);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0481");
  script_osvdb_id(22850);
  script_xref(name:"RHSA", value:"2006:0205");

  script_name(english:"CentOS 4 : libpng (CESA-2006:0205)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix a security issue are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A heap based buffer overflow bug was found in the way libpng strips
alpha channels from a PNG image. An attacker could create a carefully
crafted PNG image file in such a way that it could cause an
application linked with libpng to crash or execute arbitrary code when
the file is opened by a victim. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2006-0481 to this issue.

Please note that the vunerable libpng function is only used by TeTeX
and XEmacs on Red Hat Enterprise Linux 4.

All users of libpng are advised to update to these updated packages
which contain a backported patch that is not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0c689dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ebfe06"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5792f507"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/31");
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
if (rpm_check(release:"CentOS-4", reference:"libpng-1.2.7-1.el4.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpng-devel-1.2.7-1.el4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
