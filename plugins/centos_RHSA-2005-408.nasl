#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:408 and 
# CentOS Errata and Security Advisory 2005:408 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21935);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:21:00 $");

  script_cve_id("CVE-2005-0546");
  script_bugtraq_id(12636);
  script_osvdb_id(14089, 14090, 14091, 14092, 14093);
  script_xref(name:"RHSA", value:"2005:408");

  script_name(english:"CentOS 4 : cyrus-imapd (CESA-2005:408)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix several buffer overflow security
issues are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The cyrus-imapd package contains the core of the Cyrus IMAP server.

Several buffer overflow bugs were found in cyrus-imapd. It is possible
that an authenticated malicious user could cause the imap server to
crash. Additionally, a peer news admin could potentially execute
arbitrary code on the imap server when news is received using the
fetchnews command. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0546 to this issue.

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain cyrus-imapd version 2.2.12 to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011671.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/24");
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
if (rpm_check(release:"CentOS-4", reference:"cyrus-imapd-2.2.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-imapd-devel-2.2.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-imapd-murder-2.2.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-imapd-nntp-2.2.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-imapd-utils-2.2.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"perl-Cyrus-2.2.12-3.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
