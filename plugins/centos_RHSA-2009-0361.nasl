#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0361 and 
# CentOS Errata and Security Advisory 2009:0361 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43734);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2009-0365", "CVE-2009-0578");
  script_bugtraq_id(33966);
  script_osvdb_id(53653, 53654);
  script_xref(name:"RHSA", value:"2009:0361");

  script_name(english:"CentOS 5 : NetworkManager (CESA-2009:0361)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated NetworkManager packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

NetworkManager is a network link manager that attempts to keep a wired
or wireless network connection active at all times.

An information disclosure flaw was found in NetworkManager's D-Bus
interface. A local attacker could leverage this flaw to discover
sensitive information, such as network connection passwords and
pre-shared keys. (CVE-2009-0365)

A potential denial of service flaw was found in NetworkManager's D-Bus
interface. A local user could leverage this flaw to modify local
connection settings, preventing the system's network connection from
functioning properly. (CVE-2009-0578)

Red Hat would like to thank Ludwig Nussel for reporting these flaws
responsibly.

Users of NetworkManager should upgrade to these updated packages which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015742.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3702a85"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da1816c1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-0.7.0-4.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-devel-0.7.0-4.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-glib-0.7.0-4.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-glib-devel-0.7.0-4.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-gnome-0.7.0-4.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
