#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:2024 and 
# CentOS Errata and Security Advisory 2014:2024 respectively.
#

include("compat.inc");

if (description)
{
  script_id(80124);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/11/01 04:40:10 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");
  script_bugtraq_id(71757, 71758, 71761, 71762);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);
  script_xref(name:"RHSA", value:"2014:2024");

  script_name(english:"CentOS 6 / 7 : ntp (CESA-2014:2024)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix several security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

Multiple buffer overflow flaws were discovered in ntpd's
crypto_recv(), ctl_putdata(), and configure() functions. A remote
attacker could use either of these flaws to send a specially crafted
request packet that could crash ntpd or, potentially, execute
arbitrary code with the privileges of the ntp user. Note: the
crypto_recv() flaw requires non-default configurations to be active,
while the ctl_putdata() flaw, by default, can only be exploited via
local attackers, and the configure() flaw requires additional
authentication to exploit. (CVE-2014-9295)

It was found that ntpd automatically generated weak keys for its
internal use if no ntpdc request authentication key was specified in
the ntp.conf configuration file. A remote attacker able to match the
configured IP restrictions could guess the generated key, and possibly
use it to send ntpdc query or configuration requests. (CVE-2014-9293)

It was found that ntp-keygen used a weak method for generating MD5
keys. This could possibly allow an attacker to guess generated MD5
keys that could then be used to spoof an NTP client or server. Note:
it is recommended to regenerate any MD5 keys that had explicitly been
generated with ntp-keygen; the default installation does not contain
such keys). (CVE-2014-9294)

A missing return statement in the receive() function could potentially
allow a remote attacker to bypass NTP's authentication mechanism.
(CVE-2014-9296)

All ntp users are advised to upgrade to this updated package, which
contains backported patches to resolve these issues. After installing
the update, the ntpd daemon will restart automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4261f083"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47ca7275"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ntp-4.2.6p5-2.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-doc-4.2.6p5-2.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-perl-4.2.6p5-2.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntpdate-4.2.6p5-2.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-4.2.6p5-19.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-doc-4.2.6p5-19.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-19.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-19.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sntp-4.2.6p5-19.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
