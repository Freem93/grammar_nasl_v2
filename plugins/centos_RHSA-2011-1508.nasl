#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1508 and 
# CentOS Errata and Security Advisory 2011:1508 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56985);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3372", "CVE-2011-3481");
  script_bugtraq_id(49659, 49949);
  script_osvdb_id(75445, 76057);
  script_xref(name:"RHSA", value:"2011:1508");

  script_name(english:"CentOS 4 / 5 : cyrus-imapd (CESA-2011:1508)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix two security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

An authentication bypass flaw was found in the cyrus-imapd NNTP
server, nntpd. A remote user able to use the nntpd service could use
this flaw to read or post newsgroup messages on an NNTP server
configured to require user authentication, without providing valid
authentication credentials. (CVE-2011-3372)

A NULL pointer dereference flaw was found in the cyrus-imapd IMAP
server, imapd. A remote attacker could send a specially crafted mail
message to a victim that would possibly prevent them from accessing
their mail normally, if they were using an IMAP client that relies on
the server threading IMAP feature. (CVE-2011-3481)

Red Hat would like to thank the Cyrus IMAP project for reporting the
CVE-2011-3372 issue. Upstream acknowledges Stefan Cornelius of Secunia
Research as the original reporter of CVE-2011-3372.

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03e66f9a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e95738b8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a269129b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2368485"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-devel-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-devel-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-murder-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-murder-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-nntp-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-nntp-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-utils-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-utils-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-Cyrus-2.2.12-17.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-Cyrus-2.2.12-17.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-2.3.7-12.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-devel-2.3.7-12.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-perl-2.3.7-12.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-utils-2.3.7-12.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
