#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-825.
#

include("compat.inc");

if (description)
{
  script_id(99713);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5461");
  script_xref(name:"ALAS", value:"2017-825");
  script_xref(name:"RHSA", value:"2017:1100");

  script_name(english:"Amazon Linux AMI : nss / nss-util (ALAS-2017-825)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds write flaw was found in the way NSS performed certain
Base64-decoding operations. An attacker could use this flaw to create
a specially crafted certificate which, when parsed by NSS, could cause
it to crash or execute arbitrary code, using the permissions of the
user running an application compiled against the NSS library.
(CVE-2017-5461)

Upstream acknowledges Ronald Crane as the original reporter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-825.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update nss' to update your system.

Run 'yum update nss-util' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");
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
if (rpm_check(release:"ALA", reference:"nss-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.28.4-1.0.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-3.28.4-1.0.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-debuginfo-3.28.4-1.0.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-devel-3.28.4-1.0.52.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
