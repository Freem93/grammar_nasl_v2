#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0677 and 
# CentOS Errata and Security Advisory 2006:0677 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22426);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4570", "CVE-2006-4571");
  script_bugtraq_id(19488, 19849, 20042);
  script_xref(name:"RHSA", value:"2006:0677");

  script_name(english:"CentOS 4 : thunderbird (CESA-2006:0677)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Two flaws were found in the way Thunderbird processed certain regular
expressions. A malicious HTML email could cause a crash or possibly
execute arbitrary code as the user running Thunderbird.
(CVE-2006-4565, CVE-2006-4566)

A flaw was found in the Thunderbird auto-update verification system.
An attacker who has the ability to spoof a victim's DNS could get
Firefox to download and install malicious code. In order to exploit
this issue an attacker would also need to get a victim to previously
accept an unverifiable certificate. (CVE-2006-4567)

A flaw was found in the handling of JavaScript timed events. A
malicious HTML email could crash the browser or possibly execute
arbitrary code as the user running Thunderbird. (CVE-2006-4253)

Daniel Bleichenbacher recently described an implementation error in
RSA signature verification. For RSA keys with exponent 3 it is
possible for an attacker to forge a signature that which would be
incorrectly verified by the NSS library. (CVE-2006-4340)

A flaw was found in Thunderbird that triggered when a HTML message
contained a remote image pointing to a XBL script. An attacker could
have created a carefully crafted message which would execute
JavaScript if certain actions were performed on the email by the
recipient, even if JavaScript was disabled. (CVE-2006-4570)

A number of flaws were found in Thunderbird. A malicious HTML email
could cause a crash or possibly execute arbitrary code as the user
running Thunderbird. (CVE-2006-4571)

Users of Thunderbird are advised to upgrade to this update, which
contains Thunderbird version 1.5.0.7 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b88e61e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dd52fd2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8425dfb4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.7-0.1.el4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
