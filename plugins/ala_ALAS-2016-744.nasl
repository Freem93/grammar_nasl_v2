#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-744.
#

include("compat.inc");

if (description)
{
  script_id(93536);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:25 $");

  script_cve_id("CVE-2016-6313");
  script_xref(name:"ALAS", value:"2016-744");

  script_name(english:"Amazon Linux AMI : libgcrypt / gnupg (ALAS-2016-744)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A design flaw was found in the libgcrypt PRNG (Pseudo-Random Number
Generator). An attacker who can obtain the first 580 bytes of the PRNG
output can trivially predict the following 20 bytes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-744.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update libgcrypt' to update your system.

Run 'yum update gnupg' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
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
if (rpm_check(release:"ALA", reference:"gnupg-1.4.19-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnupg-debuginfo-1.4.19-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libgcrypt-1.5.3-12.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libgcrypt-debuginfo-1.5.3-12.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libgcrypt-devel-1.5.3-12.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg / gnupg-debuginfo / libgcrypt / libgcrypt-debuginfo / etc");
}
