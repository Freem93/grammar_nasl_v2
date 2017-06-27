#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1326 and 
# CentOS Errata and Security Advisory 2011:1326 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56249);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3193");
  script_osvdb_id(75652);
  script_xref(name:"RHSA", value:"2011:1326");

  script_name(english:"CentOS 5 : pango (CESA-2011:1326)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pango packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Pango is a library used for the layout and rendering of
internationalized text.

A buffer overflow flaw was found in HarfBuzz, an OpenType text shaping
engine used in Pango. If a user loaded a specially crafted font file
with an application that uses Pango, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2011-3193)

Users of pango are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, you must restart your system or restart the X server for
the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017752.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ac61383"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25c537bf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pango packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"pango-1.14.9-8.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pango-devel-1.14.9-8.el5.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
