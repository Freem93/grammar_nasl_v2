#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-649.
#

include("compat.inc");

if (description)
{
  script_id(88661);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/02/13 20:44:58 $");

  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-4953");
  script_xref(name:"ALAS", value:"2016-649");

  script_name(english:"Amazon Linux AMI : ntp (ALAS-2016-649)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ntpd as a client did not correctly check the
originate timestamp in received packets. A remote attacker could use
this flaw to send a crafted packet to an ntpd client that would
effectively disable synchronization with the server, or push arbitrary
offset/delay measurements to modify the time on the client.
(CVE-2015-8138)

A NULL pointer dereference flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large
amount of entries. A remote attacker could use this flaw to crash the
ntpd process. (CVE-2015-7977)

It was found that NTP does not verify peer associations of symmetric
keys when authenticating packets, which might allow remote attackers
to conduct impersonation attacks via an arbitrary trusted key.
(CVE-2015-7974)

A stack-based buffer overflow was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large
amount of entries. A remote attacker could use this flaw to crash the
ntpd process. (CVE-2015-7978)

It was found that when NTP is configured in broadcast mode, an
off-path attacker could broadcast packets with bad authentication
(wrong key, mismatched key, incorrect MAC, etc) to all clients. The
clients, upon receiving the malformed packets, would break the
association with the broadcast server. This could cause the time on
affected clients to become out of sync over a longer period of time.
(CVE-2015-7979)

A flaw was found in the way the ntpq client certain processed incoming
packets in a loop in the getresponse() function. A remote attacker
could potentially use this flaw to crash an ntpq client instance.
(CVE-2015-8158)

A flaw was found in ntpd that allows remote attackers to cause a
denial of service (ephemeral-association demobilization) by sending a
spoofed crypto-NAK packet with incorrect authentication data at a
certain time. (CVE-2016-4953)

(Updated 2016-10-18: CVE-2016-4953 was fixed in this release but was
not previously part of this errata.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-649.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ntp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ntp-4.2.6p5-36.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-debuginfo-4.2.6p5-36.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-doc-4.2.6p5-36.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntp-perl-4.2.6p5-36.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ntpdate-4.2.6p5-36.29.amzn1")) flag++;

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
