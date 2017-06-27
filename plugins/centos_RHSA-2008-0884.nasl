#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0884 and 
# CentOS Errata and Security Advisory 2008:0884 respectively.
#

include("compat.inc");

if (description)
{
  script_id(34170);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-3529");
  script_osvdb_id(48158);
  script_xref(name:"RHSA", value:"2008:0884");

  script_name(english:"CentOS 3 / 4 / 5 : libxml2 (CESA-2008:0884)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libxml2 packages provide a library that allows you to manipulate
XML files. It includes support to read, modify, and write XML and HTML
files.

A heap-based buffer overflow flaw was found in the way libxml2 handled
long XML entity names. If an application linked against libxml2
processed untrusted malformed XML content, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2008-3529)

All users of libxml2 are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?852a1bdf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a82c993"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?666e9732"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?743c5bb7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a44aabb4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e640ef98"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/12");
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
if (rpm_check(release:"CentOS-3", reference:"libxml2-2.5.10-13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-devel-2.5.10-13")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-python-2.5.10-13")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-2.6.16-12.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-devel-2.6.16-12.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-python-2.6.16-12.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
