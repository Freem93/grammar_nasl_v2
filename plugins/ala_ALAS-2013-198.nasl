#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-198.
#

include("compat.inc");

if (description)
{
  script_id(69756);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_xref(name:"ALAS", value:"2013-198");
  script_xref(name:"RHSA", value:"2013:0897");

  script_name(english:"Amazon Linux AMI : mesa (ALAS-2013-198)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds access flaw was found in Mesa. If an application
using Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox
does this), an attacker could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-1872)

It was found that Mesa did not correctly validate messages from the X
server. A malicious X server could cause an application using Mesa to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2013-1993)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-198.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mesa' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libGLU-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
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
if (rpm_check(release:"ALA", reference:"glx-utils-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-debuginfo-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libGL-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libGL-devel-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libGLU-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libGLU-devel-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libOSMesa-9.0-0.8.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mesa-libOSMesa-devel-9.0-0.8.15.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glx-utils / mesa-debuginfo / mesa-libGL / mesa-libGL-devel / etc");
}
