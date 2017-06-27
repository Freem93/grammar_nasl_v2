#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-661.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89842);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-3197", "CVE-2015-7575", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0800", "CVE-2016-2842");
  script_xref(name:"ALAS", value:"2016-661");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2016-661) (DROWN) (SLOTH)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A padding oracle flaw was found in the Secure Sockets Layer version
2.0 (SSLv2) protocol. An attacker can potentially use this flaw to
decrypt RSA-encrypted cipher text from a connection using a newer
SSL/TLS protocol version, allowing them to decrypt such connections.
This cross-protocol attack is publicly referred to as DROWN
(CVE-2016-0800). Prior to this advisory, SSLv2 has been disabled by
default in OpenSSL on the Amazon Linux AMI. However, application
configurations may still re-enable SSLv2.

A flaw was found in the way TLS 1.2 could use the MD5 hash function
for signing ServerKeyExchange and Client Authentication packets during
a TLS handshake. A man-in-the-middle attacker able to force a TLS
connection to use the MD5 hash function could use this flaw to conduct
collision attacks to impersonate a TLS server or an authenticated TLS
client. (CVE-2015-7575 , Medium)

A flaw was found in the way malicious SSLv2 clients could negotiate
SSLv2 ciphers that have been disabled on the server. This could result
in weak SSLv2 ciphers being used for SSLv2 connections, making them
vulnerable to man-in-the-middle attacks. (CVE-2015-3197 , Low)

A side-channel attack was found that makes use of cache-bank conflicts
on the Intel Sandy-Bridge microarchitecture. An attacker who has the
ability to control code in a thread running on the same hyper-threaded
core as the victim's thread that is performing decryption, could use
this flaw to recover RSA private keys. (CVE-2016-0702 , Low)

A double-free flaw was found in the way OpenSSL parsed certain
malformed DSA (Digital Signature Algorithm) private keys. An attacker
could create specially crafted DSA private keys that, when processed
by an application compiled against OpenSSL, could cause the
application to crash. (CVE-2016-0705 , Low)

An integer overflow flaw, leading to a NULL pointer dereference or a
heap-based memory corruption, was found in the way some BIGNUM
functions of OpenSSL were implemented. Applications that use these
functions with large untrusted input could crash or, potentially,
execute arbitrary code. (CVE-2016-0797 , Low)

The fmtstr function in crypto/bio/b_print.c in OpenSSL improperly
calculated string lengths, which allows remote attackers to cause a
denial of service (overflow and out-of-bounds read) or possibly have
unspecified other impact via a long string, as demonstrated by a large
amount of ASN.1 data. (CVE-2016-0799 , Low)

The doapr_outch function in crypto/bio/b_print.c in OpenSSL did not
verify that a certain memory allocation succeeds, which allows remote
attackers to cause a denial of service (out-of-bounds write or memory
consumption) or possibly have unspecified other impact via a long
string, as demonstrated by a large amount of ASN.1 data.
(CVE-2016-2842 , Low)

'(Updated on 2016-04-28: CVE-2016-2842 was fixed as part of this
update but was previously not listed in this advisory.)'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-661.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1k-14.89.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1k-14.89.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1k-14.89.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1k-14.89.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1k-14.89.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
