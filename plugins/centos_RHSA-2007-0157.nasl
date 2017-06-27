#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0157 and 
# CentOS Errata and Security Advisory 2007:0157 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25044);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-1667");
  script_bugtraq_id(23300);
  script_osvdb_id(34107, 34108);
  script_xref(name:"RHSA", value:"2007:0157");

  script_name(english:"CentOS 5 : xorg-x11-apps / libX11 (CESA-2007:0157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-apps and libX11 packages that fix a security issue
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

X.org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

An integer overflow flaw was found in the X.org XGetPixel() function.
Improper use of this function could cause an application calling it to
function improperly, possibly leading to a crash or arbitrary code
execution. (CVE-2007-1667)

Users of the X.org X11 server should upgrade to these updated
packages, which contain a backported patch and are not vulnerable to
this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7db4c12b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f904e025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libx11 and / or xorg-x11-apps packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libX11-1.0.3-8.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libX11-devel-1.0.3-8.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-apps-7.1-4.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
