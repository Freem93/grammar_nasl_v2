#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-278.
#

include("compat.inc");

if (description)
{
  script_id(72296);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-4576");
  script_xref(name:"ALAS", value:"2014-278");

  script_name(english:"Amazon Linux AMI : gnupg (ALAS-2014-278)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GnuPG 1.x before 1.4.16 generates RSA keys using sequences of
introductions with certain patterns that introduce a side channel,
which allows physically proximate attackers to extract RSA keys via a
chosen-ciphertext attack and acoustic cryptanalysis during decryption.
NOTE: applications are not typically expected to protect themselves
from acoustic side-channel attacks, since this is arguably the
responsibility of the physical device. Accordingly, issues of this
type would not normally receive a CVE identifier. However, for this
issue, the developer has specified a security policy in which GnuPG
should offer side-channel resistance, and developer-specified
security-policy violations are within the scope of CVE."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-278.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update gnupg' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gnupg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
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
if (rpm_check(release:"ALA", reference:"gnupg-1.4.16-2.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gnupg-debuginfo-1.4.16-2.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg / gnupg-debuginfo");
}
