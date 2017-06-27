#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-607.
#

include("compat.inc");

if (description)
{
  script_id(86638);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/06/13 13:30:09 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7871");
  script_xref(name:"ALAS", value:"2015-607");
  script_xref(name:"RHSA", value:"2015:1930");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2015-607)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ntpd as a client did not correctly check
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

It was found that the fix for CVE-2014-9750 was incomplete: three
issues were found in the value length checks in ntp_crypto.c, where a
packet with particular autokey operations that contained malicious
data was not always being completely validated. Receipt of these
packets can cause ntpd to crash. (CVE-2015-7691 , CVE-2015-7692 ,
CVE-2015-7702)

A potential off by one vulnerability exists in the cookedprint
functionality of ntpq. A specially crafted buffer could cause a buffer
overflow potentially resulting in null byte being written out of
bounds. (CVE-2015-7852)

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is
configured to use autokey authentication, an attacker could send
packets to ntpd that would, after several days of ongoing attack,
cause it to run out of memory. (CVE-2015-7701)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-607.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
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
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-34.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-34.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-34.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-34.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-34.27.amzn1")) flag++;

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
