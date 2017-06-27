#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-320.
#

include("compat.inc");

if (description)
{
  script_id(73438);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id("CVE-2014-0160");
  script_xref(name:"ALAS", value:"2014-320");

  script_name(english:"Amazon Linux AMI : openssl Information Disclosure Vulnerability (ALAS-2014-320)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A missing bounds check was found in the way OpenSSL handled TLS
heartbeat extension packets. This flaw could be used to reveal up to
64k of memory from a connected client or server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://heartbleed.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20140407.txt"
  );
  # http://aws.amazon.com/amazon-linux-ami/security-bulletins/ALAS-2014-320/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c70c979"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update openssl' to update your system and restart all
services that are using openssl.&nbsp; While the new package is still
named openssl-1.0.1e, it does contain the fix for CVE-2014-0160."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/09");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1e-37.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1e-37.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1e-37.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1e-37.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1e-37.66.amzn1")) flag++;

if (flag)
{
  report = rpm_report_get();
  if (!egrep(pattern:"package installed.+openssl[^0-9]*\-1\.0\.1", string:report)) exit(0, "The remote host does not use OpenSSL 1.0.1.");

  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
