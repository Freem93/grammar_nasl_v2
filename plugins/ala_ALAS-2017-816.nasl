#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-816.
#

include("compat.inc");

if (description)
{
  script_id(99529);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/24 13:52:13 $");

  script_cve_id("CVE-2017-6451", "CVE-2017-6458", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_xref(name:"ALAS", value:"2017-816");
  script_xref(name:"IAVA", value:"2017-A-0084");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2017-816)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Denial of Service via Malformed Config :

A vulnerability was discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause
ntpd to crash by sending a crafted message.(CVE-2017-6464)

Potential Overflows in ctl_put() functions :

A vulnerability was found in NTP, in the building of response packets
with custom fields. If custom fields were configured in ntp.conf with
particularly long names, inclusion of these fields in the response
packet could cause a buffer overflow, leading to a crash.
(CVE-2017-6458)

Improper use of snprintf() in mx4200_send() :

A vulnerability was found in NTP, in the legacy MX4200 refclock
implementation. If this refclock was compiled in and used, an attacker
may be able to induce stack overflow, leading to a crash or potential
code execution.(CVE-2017-6451)

Authenticated DoS via Malicious Config Option :

A vulnerability was discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause
ntpd to crash by sending a crafted message.(CVE-2017-6463)

Buffer Overflow in DPTS Clock :

A vulnerability was found in NTP, in the parsing of packets from the
/dev/datum device. A malicious device could send crafted messages,
causing ntpd to crash.(CVE-2017-6462)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-816.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-44.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-44.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-44.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-44.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-44.34.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
}
