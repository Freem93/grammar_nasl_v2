#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:782 and 
# CentOS Errata and Security Advisory 2005:782 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21858);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2001-1494", "CVE-2005-2876");
  script_bugtraq_id(14816);
  script_osvdb_id(19369, 19934);
  script_xref(name:"RHSA", value:"2005:782");

  script_name(english:"CentOS 3 / 4 : util-linux / mount (CESA-2005:782)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated util-linux and mount packages that fix two security issues are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.

The mount package contains the mount, umount, swapon and swapoff
programs.

A bug was found in the way the umount command is executed by normal
users. It may be possible for a user to gain elevated privileges if
the user is able to execute the 'umount -r' command on a mounted file
system. The file system will be re-mounted only with the 'readonly'
flag set, clearing flags such as 'nosuid' and 'noexec'. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2876 to this issue.

This update also fixes a hardlink bug in the script command for Red
Hat Enterprise Linux 2.1. If a local user places a hardlinked file
named 'typescript' in a directory they have write access to, the file
will be overwritten if the user running script has write permissions
to the destination file. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2001-1494 to this
issue.

All users of util-linux and mount should upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?455fcbf8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bfdd96b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7652da8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fabc24fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mount and / or util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:losetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/12");
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
if (rpm_check(release:"CentOS-3", reference:"losetup-2.11y-31.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mount-2.11y-31.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"util-linux-2.11y-31.11")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"util-linux-2.12a-16.EL4.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
