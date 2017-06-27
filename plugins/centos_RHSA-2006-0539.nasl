#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0539 and 
# CentOS Errata and Security Advisory 2006:0539 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22036);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-2607");
  script_osvdb_id(25850);
  script_xref(name:"RHSA", value:"2006:0539");

  script_name(english:"CentOS 4 : vixie-cron (CESA-2006:0539)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vixie-cron packages that fix a privilege escalation issue are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The vixie-cron package contains the Vixie version of cron. Cron is a
standard UNIX daemon that runs specified programs at scheduled times.

A privilege escalation flaw was found in the way Vixie Cron runs
programs; vixie-cron does not properly verify an attempt to set the
current process user id succeeded. It was possible for a malicious
local users who exhausted certain limits to execute arbitrary commands
as root via cron. (CVE-2006-2607)

All users of vixie-cron should upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/012998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?871dc651"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5a69947"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d6b6e05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vixie-cron package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vixie-cron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"vixie-cron-4.1-44.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
