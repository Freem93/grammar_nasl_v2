#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1820 and 
# CentOS Errata and Security Advisory 2011:1820 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57307);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603");
  script_bugtraq_id(51010);
  script_osvdb_id(77749, 77750, 77751);
  script_xref(name:"RHSA", value:"2011:1820");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2011:1820)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

An input sanitization flaw was found in the way the AOL Open System
for Communication in Realtime (OSCAR) protocol plug-in in Pidgin, used
by the AOL ICQ and AIM instant messaging systems, escaped certain
UTF-8 characters. A remote attacker could use this flaw to crash
Pidgin via a specially crafted OSCAR message. (CVE-2011-4601)

An input sanitization flaw was found in the way the Pidgin SILC
(Secure Internet Live Conferencing) protocol plug-in escaped certain
UTF-8 characters in channel messages. A remote attacker could use this
flaw to crash Pidgin via a specially crafted SILC message.
(CVE-2011-4603)

Multiple NULL pointer dereference flaws were found in the Jingle
extension of the Extensible Messaging and Presence Protocol (XMPP)
protocol plug-in in Pidgin. A remote attacker could use these flaws to
crash Pidgin via a specially crafted Jingle multimedia message.
(CVE-2011-4602)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Evgeny Boger as the original reporter of
CVE-2011-4601; Diego Bauche Madero from IOActive as the original
reporter of CVE-2011-4603; and Thijs Alkemade as the original reporter
of CVE-2011-4602.

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b74c4eb2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?850a42db"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018327.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15df43bb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018328.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fec6eeff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-perl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-perl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-tcl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-tcl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-perl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-perl-2.6.6-10.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.6-5.el5_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
