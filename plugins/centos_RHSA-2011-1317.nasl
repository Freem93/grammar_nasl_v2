#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1317 and 
# CentOS Errata and Security Advisory 2011:1317 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56247);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-3208");
  script_bugtraq_id(49534);
  script_osvdb_id(75307);
  script_xref(name:"RHSA", value:"2011:1317");

  script_name(english:"CentOS 4 / 5 : cyrus-imapd (CESA-2011:1317)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

A buffer overflow flaw was found in the cyrus-imapd NNTP server,
nntpd. A remote user able to use the nntpd service could use this flaw
to crash the nntpd child process or, possibly, execute arbitrary code
with the privileges of the cyrus user. (CVE-2011-3208)

Red Hat would like to thank Greg Banks for reporting this issue.

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52312c1c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33586a09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9e06acc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/018067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a876921"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-devel-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-devel-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-murder-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-murder-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-nntp-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-nntp-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cyrus-imapd-utils-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cyrus-imapd-utils-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-Cyrus-2.2.12-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-Cyrus-2.2.12-16.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-devel-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-perl-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cyrus-imapd-utils-2.3.7-12.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
