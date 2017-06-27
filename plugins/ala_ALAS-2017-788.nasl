#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-788.
#

include("compat.inc");

if (description)
{
  script_id(96806);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/27 15:06:51 $");

  script_cve_id("CVE-2016-7480", "CVE-2016-9137", "CVE-2016-9933", "CVE-2016-9934", "CVE-2016-9935", "CVE-2016-9936");
  script_xref(name:"ALAS", value:"2017-788");

  script_name(english:"Amazon Linux AMI : php70 (ALAS-2017-788)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SplObjectStorage unserialize implementation in
ext/spl/spl_observer.c in PHP before 7.0.12 does not verify that a key
is an object, which allows remote attackers to execute arbitrary code
or cause a denial of service (uninitialized memory access) via crafted
serialized data. (CVE-2016-7480)

Use-after-free vulnerability in the CURLFile implementation in
ext/curl/curl_file.c in PHP 7.x before 7.0.12 allows remote attackers
to cause a denial of service or possibly have unspecified other impact
via crafted serialized data that is mishandled during __wakeup
processing. (CVE-2016-9137)

Stack consumption vulnerability in the gdImageFillToBorder function in
gd.c in the GD Graphics Library (aka libgd) before 2.2.2, as used in
PHP 7.x before 7.0.13, allows remote attackers to cause a denial of
service (segmentation violation) via a crafted imagefilltoborder call
that triggers use of a negative color value. (CVE-2016-9933)

ext/wddx/wddx.c in PHP 7.x before 7.0.13 allows remote attackers to
cause a denial of service (NULL pointer dereference) via crafted
serialized data in a wddxPacket XML document, as demonstrated by a
PDORow string. (CVE-2016-9934)

The php_wddx_push_element function in ext/wddx/wddx.c in PHP 7.x
before 7.0.14 allows remote attackers to cause a denial of service
(out-of-bounds read and memory corruption) or possibly have
unspecified other impact via an empty boolean element in a wddxPacket
XML document. (CVE-2016-9935)

The unserialize implementation in ext/standard/var.c in PHP 7.x before
7.0.14 allows remote attackers to cause a denial of service
(use-after-free) or possibly have unspecified other impact via crafted
serialized data. This vulnerability exists because of an incomplete
fix for CVE-2015-6834 . (CVE-2016-9936)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-788.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php70' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
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
if (rpm_check(release:"ALA", reference:"php70-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-bcmath-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-cli-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-common-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dba-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dbg-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-debuginfo-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-devel-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-embedded-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-enchant-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-fpm-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gd-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gmp-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-imap-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-intl-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-json-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-ldap-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mbstring-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mcrypt-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mysqlnd-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-odbc-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-opcache-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-dblib-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pgsql-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-process-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pspell-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-recode-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-snmp-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-soap-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-tidy-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xml-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xmlrpc-7.0.14-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-zip-7.0.14-1.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php70 / php70-bcmath / php70-cli / php70-common / php70-dba / etc");
}
