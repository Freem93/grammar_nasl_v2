#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-593.
#

include("compat.inc");

if (description)
{
  script_id(85751);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/02/07 05:42:18 $");

  script_cve_id("CVE-2015-3405", "CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-7703");
  script_xref(name:"ALAS", value:"2015-593");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2015-593)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As discussed upstream, a flaw was found in the way ntpd processed
certain remote configuration packets. Note that remote configuration
is disabled by default in NTP. (CVE-2015-5146)

It was found that the :config command can be used to set the pidfile
and driftfile paths without any restrictions. A remote attacker could
use this flaw to overwrite a file on the file system with a file
containing the pid of the ntpd process (immediately) or the current
estimated drift of the system clock (in hourly intervals).
(CVE-2015-7703)

It was found that ntpd could crash due to an uninitialized variable
when processing malformed logconfig configuration commands.
(CVE-2015-5194)

It was found that ntpd exits with a segmentation fault when a
statistics type that was not enabled during compilation (e.g.
timingstats) is referenced by the statistics or filegen configuration
command. (CVE-2015-5195)

It was discovered that sntp would hang in an infinite loop when a
crafted NTP packet was received, related to the conversion of the
precision value in the packet to double. (CVE-2015-5219)

A flaw was found in the way the ntp-keygen utility generated MD5
symmetric keys on big-endian systems. An attacker could possibly use
this flaw to guess generated MD5 keys, which could then be used to
spoof an NTP client or server. (CVE-2015-3405)"
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#June_2015_NTP_Security_Vulnerabi
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1d497be"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-593.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-33.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-33.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-33.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-33.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-33.26.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
}
