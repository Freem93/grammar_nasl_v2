#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-818.
#

include("compat.inc");

if (description)
{
  script_id(99531);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2017-6188");
  script_xref(name:"ALAS", value:"2017-818");

  script_name(english:"Amazon Linux AMI : munin (ALAS-2017-818)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Munin before 2.999.6 has a local file write vulnerability when CGI
graphs are enabled. Setting multiple upper_limit GET parameters allows
overwriting any file accessible to the www-data user. (CVE-2017-6188)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-818.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update munin' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-async");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-java-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-netip-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-ruby-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (rpm_check(release:"ALA", reference:"munin-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-async-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-cgi-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-common-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-java-plugins-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-netip-plugins-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-nginx-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-node-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-ruby-plugins-2.0.30-5.38.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "munin / munin-async / munin-cgi / munin-common / munin-java-plugins / etc");
}
