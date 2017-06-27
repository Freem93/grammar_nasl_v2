#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1930 and 
# CentOS Errata and Security Advisory 2015:1930 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86611);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/06/13 13:30:09 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7704");
  script_osvdb_id(129309, 129315);
  script_xref(name:"RHSA", value:"2015:1930");

  script_name(english:"CentOS 6 / 7 : ntp (CESA-2015:1930)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

It was discovered that ntpd as a client did not correctly check
timestamps in Kiss-of-Death packets. A remote attacker could use this
flaw to send a crafted Kiss-of-Death packet to an ntpd client that
would increase the client's polling interval value, and effectively
disable synchronization with the server. (CVE-2015-7704)

It was found that ntpd did not correctly implement the threshold
limitation for the '-g' option, which is used to set the time without
any restrictions. A man-in-the-middle attacker able to intercept NTP
traffic between a connecting client and an NTP server could use this
flaw to force that client to make multiple steps larger than the panic
threshold, effectively changing the time to an arbitrary value.
(CVE-2015-5300)

Red Hat would like to thank Aanchal Malhotra, Isaac E. Cohen, and
Sharon Goldberg of Boston University for reporting these issues.

All ntp users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the update, the ntpd daemon will restart automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021447.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47fd9565"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-October/021448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17c57408"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ntp-4.2.6p5-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-doc-4.2.6p5-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-perl-4.2.6p5-5.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntpdate-4.2.6p5-5.el6.centos.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-4.2.6p5-19.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-doc-4.2.6p5-19.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-19.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-19.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sntp-4.2.6p5-19.el7.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
