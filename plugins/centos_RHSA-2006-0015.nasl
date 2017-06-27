#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0015 and 
# CentOS Errata and Security Advisory 2006:0015 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21878);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3629");
  script_xref(name:"RHSA", value:"2006:0015");

  script_name(english:"CentOS 3 : initscripts (CESA-2006:0015)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated initscripts packages that fix a privilege escalation issue and
several bugs are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The initscripts package contains the basic system scripts used to boot
your Red Hat system, change runlevels, and shut the system down
cleanly. Initscripts also contains the scripts that activate and
deactivate most network interfaces.

A bug was found in the way initscripts handled various environment
variables when the /sbin/service command is run. It is possible for a
local user with permissions to execute /sbin/service via sudo to
execute arbitrary commands as the 'root' user. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-3629
to this issue.

The following issues have also been fixed in this update :

* extraneous characters were logged on bootup.

* fsck would be attempted on filesystems marked with _netdev in
rc.sysinit before they were available.

Additionally, support for multi-core Itanium processors has been added
to redhat-support-check.

All users of initscripts should upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cca3d7e1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?279f1ca9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35d4c1d5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected initscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:initscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"initscripts-7.31.30.EL-1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"initscripts-7.31.30.EL-1.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"initscripts-7.31.30.EL-1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
