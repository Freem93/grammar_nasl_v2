#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-620.
#

include("compat.inc");

if (description)
{
  script_id(87346);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/15 14:50:16 $");

  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_xref(name:"ALAS", value:"2015-620");

  script_name(english:"Amazon Linux AMI : binutils (ALAS-2015-620)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A directory traversal flaw was found in the strip and objcopy
utilities. A specially crafted file could cause strip or objdump to
overwrite an arbitrary file writable by the user running either of
these utilities.

A buffer overflow flaw was found in the way various binutils utilities
processed certain files. If a user were tricked into processing a
specially crafted file, it could cause the utility used to process
that file to crash or, potentially, execute arbitrary code with the
privileges of the user running that utility.

An integer overflow flaw was found in the way the strings utility
processed certain files. If a user were tricked into running the
strings utility on a specially crafted file, it could cause the
strings executable to crash.

A stack-based buffer overflow flaw was found in the SREC parser of the
libbfd library. A specially crafted file could cause an application
using the libbfd library to crash or, potentially, execute arbitrary
code with the privileges of the user running that application.

A heap-based buffer overflow flaw was found in the way certain
binutils utilities processed archive files. If a user were tricked
into processing a specially crafted archive file, it could cause the
utility used to process that archive to crash or, potentially, execute
arbitrary code with the privileges of the user running that utility.

A stack-based buffer overflow flaw was found in the way various
binutils utilities processed certain files. If a user were tricked
into processing a specially crafted file, it could cause the utility
used to process that file to crash or, potentially, execute arbitrary
code with the privileges of the user running that utility.

A stack-based buffer overflow flaw was found in the way objdump
processed IHEX files. A specially crafted IHEX file could cause
objdump to crash or, potentially, execute arbitrary code with the
privileges of the user running objdump.

It was found that the fix for the CVE-2014-8485 issue was incomplete:
a heap-based buffer overflow in the objdump utility could cause it to
crash or, potentially, execute arbitrary code with the privileges of
the user running objdump when processing specially crafted files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-620.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update binutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:binutils-devel");
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
if (rpm_check(release:"ALA", reference:"binutils-2.23.52.0.1-55.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"binutils-debuginfo-2.23.52.0.1-55.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"binutils-devel-2.23.52.0.1-55.65.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
}
