#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-299.
#

include("compat.inc");

if (description)
{
  script_id(72947);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-4508", "CVE-2013-4559", "CVE-2013-4560");
  script_xref(name:"ALAS", value:"2014-299");

  script_name(english:"Amazon Linux AMI : lighttpd (ALAS-2014-299)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Use-after-free vulnerability in lighttpd before 1.4.33 allows remote
attackers to cause a denial of service (segmentation fault and crash)
via unspecified vectors that trigger FAMMonitorDirectory failures.

lighttpd before 1.4.34, when SNI is enabled, configures weak SSL
ciphers, which makes it easier for remote attackers to hijack sessions
by inserting packets into the client-server data stream or obtain
sensitive information by sniffing the network.

lighttpd before 1.4.33 does not check the return value of the (1)
setuid, (2) setgid, or (3) setgroups functions, which might cause
lighttpd to run as root if it is restarted and allows remote attackers
to gain privileges, as demonstrated by multiple calls to the clone
function that cause setuid to fail when the user process limit is
reached."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-299.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update lighttpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"lighttpd-1.4.34-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-debuginfo-1.4.34-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-fastcgi-1.4.34-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_geoip-1.4.34-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_mysql_vhost-1.4.34-4.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-fastcgi / etc");
}
