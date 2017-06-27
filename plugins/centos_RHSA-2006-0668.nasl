#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0668 and 
# CentOS Errata and Security Advisory 2006:0668 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22450);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-4019");
  script_osvdb_id(27917);
  script_xref(name:"RHSA", value:"2006:0668");

  script_name(english:"CentOS 3 / 4 : squirrelmail (CESA-2006:0668)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new squirrelmail package that fixes a security issue as well as
several bugs is now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP.

A dynamic variable evaluation flaw was found in SquirrelMail. Users
who have an account on a SquirrelMail server and are logged in could
use this flaw to overwrite variables which may allow them to read or
write other users' preferences or attachments. (CVE-2006-4019)

Users of SquirrelMail should upgrade to this erratum package, which
contains SquirrelMail 1.4.8 to correct this issue. This package also
contains a number of additional patches to correct various bugs.

Note: After installing this update, users are advised to restart their
httpd service to ensure that the new version functions correctly."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b1cf35"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?709023f7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2daeaa7d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89b35936"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ae6919a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b814bf0c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/11");
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
if (rpm_check(release:"CentOS-3", reference:"squirrelmail-1.4.8-2.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squirrelmail-1.4.8-2.el4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
