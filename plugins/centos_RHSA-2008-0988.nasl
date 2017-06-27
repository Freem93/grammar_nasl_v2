#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0988 and 
# CentOS Errata and Security Advisory 2008:0988 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37692);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-4225", "CVE-2008-4226");
  script_osvdb_id(49992, 49993);
  script_xref(name:"RHSA", value:"2008:0988");

  script_name(english:"CentOS 3 / 4 / 5 : libxml2 (CESA-2008:0988)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix security issues are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

libxml2 is a library for parsing and manipulating XML files. It
includes support for reading, modifying, and writing XML and HTML
files.

An integer overflow flaw causing a heap-based buffer overflow was
found in the libxml2 XML parser. If an application linked against
libxml2 processed untrusted, malformed XML content, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2008-4226)

A denial of service flaw was discovered in the libxml2 XML parser. If
an application linked against libxml2 processed untrusted, malformed
XML content, it could cause the application to enter an infinite loop.
(CVE-2008-4225)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

Users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60319eba"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fb5a422"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5937356"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?672d2ec3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06d5e5f6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbc5a9d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dbe2161"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90ed6079"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015430.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0de8c8ac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015431.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56f9a9cc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libxml2-2.5.10-14")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-devel-2.5.10-14")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-python-2.5.10-14")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libxml2-2.6.16-12.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-devel-2.6.16-12.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-python-2.6.16-12.6")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
