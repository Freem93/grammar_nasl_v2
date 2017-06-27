#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0115 and 
# CentOS Errata and Security Advisory 2010:0115 respectively.
#

include("compat.inc");

if (description)
{
  script_id(44671);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_bugtraq_id(38294);
  script_osvdb_id(62439, 62440);
  script_xref(name:"RHSA", value:"2010:0115");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2010:0115)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix three security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

An input sanitization flaw was found in the way Pidgin's MSN protocol
implementation handled MSNSLP invitations. A remote attacker could
send a specially crafted INVITE request that would cause a denial of
service (memory corruption and Pidgin crash). (CVE-2010-0277)

A denial of service flaw was found in Finch's XMPP chat
implementation, when using multi-user chat. If a Finch user in a
multi-user chat session were to change their nickname to contain the
HTML 'br' element, it would cause Finch to crash. (CVE-2010-0420)

Red Hat would like to thank Sadrul Habib Chowdhury of the Pidgin
project for responsibly reporting the CVE-2010-0420 issue.

A denial of service flaw was found in the way Pidgin processed
emoticon images. A remote attacker could flood the victim with
emoticon images during mutual communication, leading to excessive CPU
use. (CVE-2010-0423)

These packages upgrade Pidgin to version 2.6.6. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users are advised to upgrade to these updated packages,
which correct these issues. Pidgin must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40b0472b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd79f59a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0347372a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cf9c55c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/22");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-perl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-perl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-tcl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-tcl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-perl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-perl-2.6.6-1.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.6-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
