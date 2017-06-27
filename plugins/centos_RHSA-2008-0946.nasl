#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0946 and 
# CentOS Errata and Security Advisory 2008:0946 respectively.
#

include("compat.inc");

if (description)
{
  script_id(34463);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-3916");
  script_xref(name:"RHSA", value:"2008:0946");

  script_name(english:"CentOS 3 / 4 / 5 : ed (CESA-2008:0946)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ed package that fixes one security issue is now available
for Red Hat Enterprise Linux 2.1, 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ed is a line-oriented text editor, used to create, display, and modify
text files (both interactively and via shell scripts).

A heap-based buffer overflow was discovered in the way ed, the GNU
line editor, processed long file names. An attacker could create a
file with a specially crafted name that could possibly execute an
arbitrary code when opened in the ed editor. (CVE-2008-3916)

Users of ed should upgrade to this updated package, which contains a
backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4819b6c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4313bf3e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeddf2cc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7178e112"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8011117b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35deaae1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff40cdc5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16b5d2b8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ed package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ed");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/22");
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
if (rpm_check(release:"CentOS-3", reference:"ed-0.2-33.30E.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ed-0.2-36.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ed-0.2-36.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ed-0.2-36.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ed-0.2-39.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
