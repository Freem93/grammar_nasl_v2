#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-217.
#

include("compat.inc");

if (description)
{
  script_id(70221);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2013-0791", "CVE-2013-1620");
  script_xref(name:"ALAS", value:"2013-217");
  script_xref(name:"RHSA", value:"2013:1144");

  script_name(english:"Amazon Linux AMI : nss (ALAS-2013-217)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that NSS leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL or
DTLS server as a padding oracle. (CVE-2013-1620)

An out-of-bounds memory read flaw was found in the way NSS decoded
certain certificates. If an application using NSS decoded a malformed
certificate, it could cause the application to crash. (CVE-2013-0791)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-217.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nss' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"nss-3.14.3-4.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.14.3-4.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.14.3-4.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.14.3-4.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.14.3-4.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.14.3-4.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
