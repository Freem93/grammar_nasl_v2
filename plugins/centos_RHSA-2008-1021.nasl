#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1021 and 
# CentOS Errata and Security Advisory 2008:1021 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35172);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-3863", "CVE-2008-4306", "CVE-2008-5078");
  script_osvdb_id(52158, 52159);
  script_xref(name:"RHSA", value:"2008:1021");

  script_name(english:"CentOS 3 / 4 : enscript (CESA-2008:1021)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated enscript packages that fixes several security issues is now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU enscript converts ASCII files to PostScript(R) language files and
spools the generated output to a specified printer or saves it to a
file. Enscript can be extended to handle different output media and
includes options for customizing printouts.

Several buffer overflow flaws were found in GNU enscript. An attacker
could craft an ASCII file in such a way that it could execute
arbitrary commands if the file was opened with enscript with the
'special escapes' option (-e or --escapes) enabled. (CVE-2008-3863,
CVE-2008-4306, CVE-2008-5078)

All users of enscript should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2b0adc6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dedda32"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88da5559"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30c7d805"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?594dab84"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f9d619e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected enscript package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:enscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/16");
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
if (rpm_check(release:"CentOS-3", reference:"enscript-1.6.1-24.7")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"enscript-1.6.1-33.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"enscript-1.6.1-33.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"enscript-1.6.1-33.el4_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
