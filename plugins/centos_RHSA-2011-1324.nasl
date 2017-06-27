#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1324 and 
# CentOS Errata and Security Advisory 2011:1324 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56248);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2007-0242", "CVE-2011-3193");
  script_bugtraq_id(23269);
  script_xref(name:"RHSA", value:"2011:1324");

  script_name(english:"CentOS 5 : qt4 (CESA-2011:1324)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qt4 packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Qt 4 is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A flaw in the way Qt 4 expanded certain UTF-8 characters could be used
to prevent a Qt 4 based application from properly sanitizing user
input. Depending on the application, this could allow an attacker to
perform directory traversal, or for web applications, a cross-site
scripting (XSS) attack. (CVE-2007-0242)

A buffer overflow flaw was found in the harfbuzz module in Qt 4. If a
user loaded a specially crafted font file with an application linked
against Qt 4, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3193)

Users of Qt 4 should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt 4 libraries must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c2537f5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017755.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?134d4869"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt4-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"qt4-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-devel-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-doc-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-mysql-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-odbc-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-postgresql-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt4-sqlite-4.2.1-1.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
