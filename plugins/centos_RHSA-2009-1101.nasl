#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1101 and 
# CentOS Errata and Security Advisory 2009:1101 respectively.
#

include("compat.inc");

if (description)
{
  script_id(39424);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2004-2541", "CVE-2006-4262", "CVE-2009-0148", "CVE-2009-1577");
  script_bugtraq_id(34805);
  script_osvdb_id(56399);
  script_xref(name:"RHSA", value:"2009:1101");

  script_name(english:"CentOS 3 : cscope (CESA-2009:1101)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cscope package that fixes multiple security issues is now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

cscope is a mature, ncurses-based, C source-code tree browsing tool.

Multiple buffer overflow flaws were found in cscope. An attacker could
create a specially crafted source code file that could cause cscope to
crash or, possibly, execute arbitrary code when browsed with cscope.
(CVE-2004-2541, CVE-2006-4262, CVE-2009-0148, CVE-2009-1577)

All users of cscope are advised to upgrade to this updated package,
which contains backported patches to fix these issues. All running
instances of cscope must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64d14d9d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015972.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f251bd49"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cscope package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cscope");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cscope-15.5-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cscope-15.5-16.RHEL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
