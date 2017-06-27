#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-520.
#

include("compat.inc");

if (description)
{
  script_id(83271);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/26 13:52:05 $");

  script_cve_id("CVE-2015-1798", "CVE-2015-1799");
  script_xref(name:"ALAS", value:"2015-520");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2015-520)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The symmetric-key feature in the receive function in ntp_proto.c in
ntpd in NTP 4.x before 4.2.8p2 requires a correct MAC only if the MAC
field has a nonzero length, which makes it easier for
man-in-the-middle attackers to spoof packets by omitting the MAC.
(CVE-2015-1798)

The symmetric-key feature in the receive function in ntp_proto.c in
ntpd in NTP 3.x and 4.x before 4.2.8p2 performs state-variable updates
upon receiving certain invalid packets, which makes it easier for
man-in-the-middle attackers to cause a denial of service
(synchronization loss) by spoofing the source IP address of a peer.
(CVE-2015-1799)

This update also addresses leap-second handling. With older ntp
versions, the -x option was sometimes used as a workaround to avoid
kernel inserting/deleting leap seconds by stepping the clock and
possibly upsetting running applications. That no longer works with
4.2.6 as ntpd steps the clock itself when a leap second occurs. The
fix is to treat the one second offset gained during leap second as a
normal offset and check the stepping threshold (set by -x or tinker
step) to decide if a step should be applied. See this forum post for
more information on the Amazon Linux AMI's leap-second handling."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1196635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://forums.aws.amazon.com/ann.jspa?annID=3064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-520.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-30.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-30.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-30.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-30.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-30.24.amzn1")) flag++;

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
