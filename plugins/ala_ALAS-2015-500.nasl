#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-500.
#

include("compat.inc");

if (description)
{
  script_id(82507);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/02 13:36:27 $");

  script_cve_id("CVE-2014-3564");
  script_xref(name:"ALAS", value:"2015-500");

  script_name(english:"Amazon Linux AMI : gpgme (ALAS-2015-500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple heap-based buffer overflows in the status_handler function in
(1) engine-gpgsm.c and (2) engine-uiserver.c in GPGME before 1.5.1
allow remote attackers to cause a denial of service (crash) and
possibly execute arbitrary code via vectors related to 'different line
lengths in a specific order.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-500.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update gpgme' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gpgme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gpgme-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gpgme-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");
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
if (rpm_check(release:"ALA", reference:"gpgme-1.4.3-5.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gpgme-debuginfo-1.4.3-5.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gpgme-devel-1.4.3-5.15.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpgme / gpgme-debuginfo / gpgme-devel");
}
