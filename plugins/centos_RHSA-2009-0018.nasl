#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0018 and 
# CentOS Errata and Security Advisory 2009:0018 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35312);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:43:05 $");

  script_cve_id("CVE-2008-2383");
  script_bugtraq_id(33060);
  script_xref(name:"RHSA", value:"2009:0018");

  script_name(english:"CentOS 3 / 4 / 5 : xterm (CESA-2009:0018)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xterm package to correct a security issue is now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The xterm program is a terminal emulator for the X Window System.

A flaw was found in the xterm handling of Device Control Request
Status String (DECRQSS) escape sequences. An attacker could create a
malicious text file (or log entry, if unfiltered) that could run
arbitrary commands if read by a victim inside an xterm window.
(CVE-2008-2383)

All xterm users are advised to upgrade to the updated package, which
contains a backported patch to resolve this issue. All running
instances of xterm must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82deff0c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2869574"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4899832"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9db6aa34"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bd76aab"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6337fee2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b8c7dda"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e9e4e34"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xterm package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xterm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/08");
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
if (rpm_check(release:"CentOS-3", reference:"xterm-179-11.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"xterm-192-8.el4_7.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"xterm-215-5.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
