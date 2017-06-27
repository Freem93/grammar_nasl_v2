#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-354.
#

include("compat.inc");

if (description)
{
  script_id(78297);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2013-7041", "CVE-2014-2583");
  script_xref(name:"ALAS", value:"2014-354");

  script_name(english:"Amazon Linux AMI : pam (ALAS-2014-354)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple directory traversal vulnerabilities in pam_timestamp.c in the
pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users
to create aribitrary files or possibly bypass authentication via a ..
(dot dot) in the (1) PAM_RUSER value to the get_ruser function or (2)
PAM_TTY value to the check_tty funtion, which is used by the
format_timestamp_name function.

The pam_userdb module for Pam uses a case-insensitive method to
compare hashed passwords, which makes it easier for attackers to guess
the password via a brute-force attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-354.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update pam' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"pam-1.1.8-9.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam-debuginfo-1.1.8-9.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam-devel-1.1.8-9.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam / pam-debuginfo / pam-devel");
}
