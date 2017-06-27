#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-628.
#

include("compat.inc");

if (description)
{
  script_id(87354);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/17 15:21:21 $");

  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_xref(name:"ALAS", value:"2015-628");

  script_name(english:"Amazon Linux AMI : libxml2 (ALAS-2015-628)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way the libxml2 library
parsed certain XML files. An attacker could provide a specially
crafted XML file that, when parsed by an application using libxml2,
could cause that application to use an excessive amount of memory.

The xmlParseConditionalSections function in parser.c in libxml2 does
not properly skip intermediary entities when it stops parsing invalid
input, which allows context-dependent attackers to cause a denial of
service (out-of-bounds read and crash) via crafted XML data, a
different vulnerability than CVE-2015-7941 .

libxml2 2.9.2 does not properly stop parsing invalid input, which
allows context-dependent attackers to cause a denial of service
(out-of-bounds read and libxml2 crash) via crafted XML data to the (1)
xmlParseEntityDecl or (2) xmlParseConditionalSections function in
parser.c, as demonstrated by non-terminated entities.

A heap-based buffer overflow vulnerability was found in
xmlDictComputeFastQKey in dict.c.

A heap-based buffer overflow read in xmlParseMisc was found.

A heap-based buffer overflow was found in xmlGROW allowing the
attacker to read the memory out of bounds.

A buffer overread in xmlNextChar was found, causing segmentation fault
when compiled with ASAN.

Heap-based buffer overflow was found in xmlParseXmlDecl. When
conversion failure happens, parser continues to extract more errors
which may lead to unexpected behaviour.

Stack-based buffer overread vulnerability with HTML parser in push
mode in xmlSAX2TextNode causing segmentation fault when compiled with
ASAN.

A vulnerability in libxml2 was found causing DoS by exhausting CPU
when parsing specially crafted XML document.

An out-of-bounds heap read in xmlParseXMLDecl happens when a file
containing unfinished xml declaration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-628.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libxml2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
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
if (rpm_check(release:"ALA", reference:"libxml2-2.9.1-6.2.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-debuginfo-2.9.1-6.2.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-devel-2.9.1-6.2.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python26-2.9.1-6.2.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python27-2.9.1-6.2.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-static-2.9.1-6.2.50.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / libxml2-python26 / etc");
}
