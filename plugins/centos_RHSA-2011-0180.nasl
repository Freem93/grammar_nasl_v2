#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0180 and 
# CentOS Errata and Security Advisory 2011:0180 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51886);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:51:59 $");

  script_cve_id("CVE-2011-0020");
  script_bugtraq_id(45842);
  script_xref(name:"RHSA", value:"2011:0180");

  script_name(english:"CentOS 4 : pango (CESA-2011:0180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pango and evolution28-pango packages that fix one security
issue are now available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Pango is a library used for the layout and rendering of
internationalized text.

An input sanitization flaw, leading to a heap-based buffer overflow,
was found in the way Pango displayed font files when using the
FreeType font engine back end. If a user loaded a malformed font file
with an application that uses Pango, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2011-0020)

Users of pango and evolution28-pango are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. After installing the updated packages, you must restart your
system or restart your X session for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-February/017249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca9a5050"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-February/017250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a549cea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pango packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution28-pango-1.14.9-13.el4_10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution28-pango-1.14.9-13.el4_10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution28-pango-devel-1.14.9-13.el4_10")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution28-pango-devel-1.14.9-13.el4_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
