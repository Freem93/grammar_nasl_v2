#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1427 and 
# CentOS Errata and Security Advisory 2009:1427 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40893);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");
  script_bugtraq_id(25495, 29705);
  script_xref(name:"RHSA", value:"2009:1427");

  script_name(english:"CentOS 3 / 4 / 5 : fetchmail (CESA-2009:1427)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated fetchmail package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, such as SLIP and PPP connections.

It was discovered that fetchmail is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse fetchmail into
accepting it by mistake. (CVE-2009-2666)

A flaw was found in the way fetchmail handles rejections from a remote
SMTP server when sending warning mail to the postmaster. If fetchmail
sent a warning mail to the postmaster of an SMTP server and that SMTP
server rejected it, fetchmail could crash. (CVE-2007-4565)

A flaw was found in fetchmail. When fetchmail is run in double verbose
mode ('-v -v'), it could crash upon receiving certain, malformed mail
messages with long headers. A remote attacker could use this flaw to
cause a denial of service if fetchmail was also running in daemon mode
('-d'). (CVE-2008-2711)

Note: when using SSL-enabled services, it is recommended that the
fetchmail '--sslcertck' option be used to enforce strict SSL
certificate checking.

All fetchmail users should upgrade to this updated package, which
contains backported patches to correct these issues. If fetchmail is
running in daemon mode, it must be restarted for this update to take
effect (use the 'fetchmail --quit' command to stop the fetchmail
process)."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c209e072"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bf83d42"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08230bc8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fce5330"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01b7bdb7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a26e6fc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92dc472c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?342338ab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"fetchmail-6.2.0-3.el3.5")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"fetchmail-6.2.0-3.el3.5")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fetchmail-6.2.5-6.0.1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fetchmail-6.2.5-6.0.1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"fetchmail-6.3.6-1.1.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
