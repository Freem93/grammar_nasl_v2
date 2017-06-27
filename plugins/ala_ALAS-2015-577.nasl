#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-577.
#

include("compat.inc");

if (description)
{
  script_id(85232);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/05 14:41:22 $");

  script_cve_id("CVE-2014-3591", "CVE-2014-5270", "CVE-2015-0837");
  script_xref(name:"ALAS", value:"2015-577");

  script_name(english:"Amazon Linux AMI : libgcrypt (ALAS-2015-577)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix a side-channel attack on data-dependent timing variations in
modular exponentiation, which can potentially lead to an information
leak. (CVE-2015-0837)

Fix a side-channel attack which can potentially lead to an information
leak. (CVE-2014-3591)

Libgcrypt before 1.5.4, as used in GnuPG and other products, does not
properly perform ciphertext normalization and ciphertext
randomization, which makes it easier for physically proximate
attackers to conduct key-extraction attacks by leveraging the ability
to collect voltage data from exposed metal, a different vector than
CVE-2013-4576 , which was fixed in ALAS-2014-278. (CVE-2014-5270)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-577.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libgcrypt' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");
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
if (rpm_check(release:"ALA", reference:"libgcrypt-1.5.3-12.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libgcrypt-debuginfo-1.5.3-12.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libgcrypt-devel-1.5.3-12.18.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt / libgcrypt-debuginfo / libgcrypt-devel");
}
