#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-257.
#

include("compat.inc");

if (description)
{
  script_id(71397);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2012-4453");
  script_xref(name:"ALAS", value:"2013-257");
  script_xref(name:"RHSA", value:"2013:1674");

  script_name(english:"Amazon Linux AMI : dracut (ALAS-2013-257)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that dracut created initramfs images as world
readable. A local user could possibly use this flaw to obtain
sensitive information from these files, such as iSCSI authentication
passwords, encrypted root file system crypttab passwords, or other
information. (CVE-2012-4453)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-257.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dracut' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-caps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-fips-aesni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dracut-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");
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
if (rpm_check(release:"ALA", reference:"dracut-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-caps-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-fips-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-fips-aesni-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-generic-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-kernel-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-network-004-336.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dracut-tools-004-336.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-caps / dracut-fips / dracut-fips-aesni / etc");
}
