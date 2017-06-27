#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1060 and 
# CentOS Errata and Security Advisory 2009:1060 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43751);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2008-2927", "CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376", "CVE-2009-2694");
  script_bugtraq_id(35067);
  script_osvdb_id(54646, 54647, 54648, 54649);
  script_xref(name:"RHSA", value:"2009:1060");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2009:1060)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A buffer overflow flaw was found in the way Pidgin initiates file
transfers when using the Extensible Messaging and Presence Protocol
(XMPP). If a Pidgin client initiates a file transfer, and the remote
target sends a malformed response, it could cause Pidgin to crash or,
potentially, execute arbitrary code with the permissions of the user
running Pidgin. This flaw only affects accounts using XMPP, such as
Jabber and Google Talk. (CVE-2009-1373)

A denial of service flaw was found in Pidgin's QQ protocol decryption
handler. When the QQ protocol decrypts packet information, heap data
can be overwritten, possibly causing Pidgin to crash. (CVE-2009-1374)

A flaw was found in the way Pidgin's PurpleCircBuffer object is
expanded. If the buffer is full when more data arrives, the data
stored in this buffer becomes corrupted. This corrupted data could
result in confusing or misleading data being presented to the user, or
possibly crash Pidgin. (CVE-2009-1375)

It was discovered that on 32-bit platforms, the Red Hat Security
Advisory RHSA-2008:0584 provided an incomplete fix for the integer
overflow flaw affecting Pidgin's MSN protocol handler. If a Pidgin
client receives a specially crafted MSN message, it may be possible to
execute arbitrary code with the permissions of the user running
Pidgin. (CVE-2009-1376)

Note: By default, when using an MSN account, only users on your buddy
list can send you messages. This prevents arbitrary MSN users from
exploiting this flaw.

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015937.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"finch-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"finch-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpurple-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpurple-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpurple-perl-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpurple-tcl-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"pidgin-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"pidgin-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"pidgin-perl-2.5.5-2.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.5.5-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
