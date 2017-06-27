#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-683.
#

include("compat.inc");

if (description)
{
  script_id(90365);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-0787");
  script_xref(name:"ALAS", value:"2016-683");

  script_name(english:"Amazon Linux AMI : libssh2 (ALAS-2016-683)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A type confusion issue was found in the way libssh2 generated
ephemeral secrets for the diffie-hellman-group1 and
diffie-hellman-group14 key exchange methods. This would cause an SSHv2
Diffie-Hellman handshake to use significantly less secure random
parameters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-683.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libssh2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
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
if (rpm_check(release:"ALA", reference:"libssh2-1.4.2-2.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libssh2-debuginfo-1.4.2-2.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libssh2-devel-1.4.2-2.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libssh2-docs-1.4.2-2.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2 / libssh2-debuginfo / libssh2-devel / libssh2-docs");
}
