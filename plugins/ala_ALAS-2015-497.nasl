#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-497.
#

include("compat.inc");

if (description)
{
  script_id(82046);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/31 13:42:01 $");

  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9621", "CVE-2014-9653");
  script_xref(name:"ALAS", value:"2015-497");

  script_name(english:"Amazon Linux AMI : file (ALAS-2015-497)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ELF parser in file 5.08 through 5.21 allows remote attackers to
cause a denial of service via a large number of notes. (CVE-2014-9620)

The ELF parser (readelf.c) in file before 5.21 allows remote attackers
to cause a denial of service (CPU consumption or crash) via a large
number of (1) program or (2) section headers or (3) invalid
capabilities. (CVE-2014-8116)

It was reported that a malformed elf file can cause file urility to
access invalid memory. (CVE-2014-9653)

The ELF parser in file 5.16 through 5.21 allows remote attackers to
cause a denial of service via a long string. (CVE-2014-9621)

softmagic.c in file before 5.21 does not properly limit recursion,
which allows remote attackers to cause a denial of service (CPU
consumption or crash) via unspecified vectors. (CVE-2014-8117)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-497.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update file' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
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
if (rpm_check(release:"ALA", reference:"file-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-debuginfo-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-devel-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-libs-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-static-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-magic-5.22-2.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-magic-5.22-2.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-devel / file-libs / file-static / etc");
}
