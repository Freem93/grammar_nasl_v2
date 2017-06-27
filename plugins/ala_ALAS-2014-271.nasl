#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-271.
#

include("compat.inc");

if (description)
{
  script_id(72289);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_xref(name:"ALAS", value:"2014-271");
  script_xref(name:"RHSA", value:"2013:1850");

  script_name(english:"Amazon Linux AMI : openjpeg (ALAS-2014-271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple heap-based buffer overflow flaws were found in OpenJPEG. An
attacker could create a specially crafted OpenJPEG image that, when
opened, could cause an application using openjpeg to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-6045 , CVE-2013-6054)

Multiple denial of service flaws were found in OpenJPEG. An attacker
could create a specially crafted OpenJPEG image that, when opened,
could cause an application using openjpeg to crash (CVE-2013-1447 ,
CVE-2013-6052)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-271.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openjpeg' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-libs");
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
if (rpm_check(release:"ALA", reference:"openjpeg-1.3-10.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-debuginfo-1.3-10.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-devel-1.3-10.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-libs-1.3-10.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg / openjpeg-debuginfo / openjpeg-devel / openjpeg-libs");
}
