#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0155 and 
# CentOS Errata and Security Advisory 2008:0155 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31302);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2008-0411");
  script_bugtraq_id(28017);
  script_osvdb_id(42310);
  script_xref(name:"RHSA", value:"2008:0155");

  script_name(english:"CentOS 3 / 4 / 5 : ghostscript (CESA-2008:0155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ghostscript packages that fix a security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Ghostscript is a program for displaying PostScript files, or printing
them to non-PostScript printers.

Chris Evans from the Google Security Team reported a stack-based
buffer overflow flaw in Ghostscript's zseticcspace() function. An
attacker could create a malicious PostScript file that would cause
Ghostscript to execute arbitrary code when opened. (CVE-2008-0411)

These updated packages also fix a bug, which prevented the pxlmono
printer driver from producing valid output on Red Hat Enterprise Linux
4.

All users of ghostscript are advised to upgrade to these updated
packages, which contain a backported patch to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?882199d8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa2cbd3f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f28d8de"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ec17a6f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d16806ed"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e317e54a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b1b3d2e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90edd87b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"ghostscript-7.05-32.1.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ghostscript-devel-7.05-32.1.13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"hpijs-1.3-32.1.13")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-7.07-33.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-devel-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-devel-7.07-33.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-devel-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-gtk-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-gtk-7.07-33.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-gtk-7.07-33.2.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ghostscript-8.15.2-9.1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ghostscript-devel-8.15.2-9.1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ghostscript-gtk-8.15.2-9.1.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
