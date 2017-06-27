#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-596.
#

include("compat.inc");

if (description)
{
  script_id(86074);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/23 14:26:24 $");

  script_cve_id("CVE-2015-2730");
  script_xref(name:"ALAS", value:"2015-596");
  script_xref(name:"RHSA", value:"2015:1699");

  script_name(english:"Amazon Linux AMI : nss-softokn (ALAS-2015-596)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-596.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nss-softokn' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");
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
if (rpm_check(release:"ALA", reference:"nss-softokn-3.16.2.3-13.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-debuginfo-3.16.2.3-13.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-devel-3.16.2.3-13.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-freebl-3.16.2.3-13.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-freebl-devel-3.16.2.3-13.37.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss-softokn / nss-softokn-debuginfo / nss-softokn-devel / etc");
}
