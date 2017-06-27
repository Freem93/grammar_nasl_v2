#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0843 and 
# CentOS Errata and Security Advisory 2011:0843 respectively.
#

include("compat.inc");

if (description)
{
  script_id(54937);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2011-1720");
  script_bugtraq_id(47778);
  script_osvdb_id(72259);
  script_xref(name:"RHSA", value:"2011:0843");

  script_name(english:"CentOS 4 / 5 : postfix (CESA-2011:0843)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postfix packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH
(SASL), and TLS.

A heap-based buffer over-read flaw was found in the way Postfix
performed SASL handlers management for SMTP sessions, when Cyrus SASL
authentication was enabled. A remote attacker could use this flaw to
cause the Postfix smtpd server to crash via a specially crafted SASL
authentication request. The smtpd process was automatically restarted
by the postfix master process after the time configured with
service_throttle_time elapsed. (CVE-2011-1720)

Note: Cyrus SASL authentication for Postfix is not enabled by default.

Red Hat would like to thank the CERT/CC for reporting this issue.
Upstream acknowledges Thomas Jarosch of Intra2net AG as the original
reporter.

Users of Postfix are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the postfix service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36deeb38"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c97eea45"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017595.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017596.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix-pflogsumm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postfix-2.2.10-1.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postfix-2.2.10-1.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postfix-pflogsumm-2.2.10-1.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postfix-pflogsumm-2.2.10-1.5.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postfix-2.3.3-2.3.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postfix-pflogsumm-2.3.3-2.3.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
