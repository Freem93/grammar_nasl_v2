#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-513.
#

include("compat.inc");

if (description)
{
  script_id(83056);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/30 13:50:09 $");

  script_cve_id("CVE-2013-7423", "CVE-2015-1781");
  script_xref(name:"ALAS", value:"2015-513");
  script_xref(name:"RHSA", value:"2015:0863");

  script_name(english:"Amazon Linux AMI : glibc (ALAS-2015-513)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way glibc's gethostbyname_r()
and other related functions computed the size of a buffer when passed
a misaligned buffer as input. An attacker able to make an application
call any of these functions with a misaligned buffer could use this
flaw to crash the application or, potentially, execute arbitrary code
with the permissions of the user running the application.
(CVE-2015-1781)

It was discovered that, under certain circumstances, glibc's
getaddrinfo() function would send DNS queries to random file
descriptors. An attacker could potentially use this flaw to send DNS
queries to unintended recipients, resulting in information disclosure
or data loss due to the application encountering corrupted data.
(CVE-2013-7423)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-513.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update glibc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
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
if (rpm_check(release:"ALA", reference:"glibc-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-common-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-devel-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-headers-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-static-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-utils-2.17-55.142.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nscd-2.17-55.142.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
