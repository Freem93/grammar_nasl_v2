#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1646 and 
# CentOS Errata and Security Advisory 2009:1646 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43070);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"RHSA", value:"2009:1646");

  script_name(english:"CentOS 3 / 4 / 5 : libtool (CESA-2009:1646)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtool packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU Libtool is a set of shell scripts which automatically configure
UNIX, Linux, and similar operating systems to generically build shared
libraries.

A flaw was found in the way GNU Libtool's libltdl library looked for
modules to load. It was possible for libltdl to load and run modules
from an arbitrary library in the current working directory. If a local
attacker could trick a local user into running an application (which
uses libltdl) from an attacker-controlled directory containing a
malicious Libtool control file (.la), the attacker could possibly
execute arbitrary code with the privileges of the user running the
application. (CVE-2009-3736)

All libtool users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, applications using the libltdl library must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?852669f2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd3a6457"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?693c33dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04b04021"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016382.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ce89a06"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6ab47c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtool packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtool-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtool-ltdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtool-ltdl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libtool-1.4.3-7")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libtool-1.4.3-7")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libtool-libs-1.4.3-7")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libtool-libs-1.4.3-7")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtool-1.5.6-5.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtool-1.5.6-5.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtool-libs-1.5.6-5.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtool-libs-1.5.6-5.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libtool-1.5.22-7.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtool-ltdl-1.5.22-7.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtool-ltdl-devel-1.5.22-7.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
