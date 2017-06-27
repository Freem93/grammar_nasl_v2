#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-426.
#

include("compat.inc");

if (description)
{
  script_id(78484);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/07 15:17:40 $");

  script_cve_id("CVE-2014-3566");
  script_xref(name:"ALAS", value:"2014-426");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2014-426) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bodo Moller, Thai Duong and Krzysztof Kotowicz of Google discovered a
flaw in the design of SSL version 3.0 that would allow an attacker to
calculate the plaintext of secure connections, allowing, for example,
secure HTTP cookies to be stolen.

http://googleonlinesecurity.blogspot.com/2014/10/this-poodle-bites-exp
loiting-ssl-30.html

https://www.openssl.org/~bodo/ssl-poodle.pdf

Special notes :

We have backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI
repositories with updated openssl packages that fix CVE-2014-3566 .

For 2014.09 Amazon Linux AMIs, 'openssl-1.0.1i-1.79.amzn1' addresses
this CVE. Running 'yum clean all' followed by 'yum update openssl'
will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories,
'openssl-1.0.1i-1.79.amzn1' also addresses this CVE. Running 'yum
clean all' followed by 'yum update openssl' will install the fixed
package.

For Amazon Linux AMIs 'locked' to the 2013.09 or 2013.03 repositories,
'openssl-1.0.1e-4.60.amzn1' addresses this CVE. Running 'yum clean
all' followed by 'yum update openssl' will install the fixed package.

If you are using a pre-2013.03 Amazon Linux AMI, we encourage you to
move to a newer version of the Amazon Linux AMI as soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-426.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update openssl' to update your system. Note that you may need
to run 'yum clean all' first."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1i-1.79.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1i-1.79.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1i-1.79.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1i-1.79.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1i-1.79.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
