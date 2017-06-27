#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-345.
#

include("compat.inc");

if (description)
{
  script_id(78288);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-0172");
  script_xref(name:"ALAS", value:"2014-345");

  script_name(english:"Amazon Linux AMI : elfutils (ALAS-2014-345)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Integer overflow in the check_section function in dwarf_begin_elf.c in
the libdw library, as used in elfutils 0.153 and possibly through
0.158 allows remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a malformed
compressed debug section in an ELF file, which triggers a heap-based
buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-345.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update elfutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libelf-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
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
if (rpm_check(release:"ALA", reference:"elfutils-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-debuginfo-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-devel-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-devel-static-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-libelf-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-libelf-devel-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-libelf-devel-static-0.158-3.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"elfutils-libs-0.158-3.16.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-devel / etc");
}
