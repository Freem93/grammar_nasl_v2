#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-743.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93744);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:42 $");

  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_xref(name:"ALAS", value:"2016-743");

  script_name(english:"Amazon Linux AMI : libarchive (ALAS-2016-743)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way libarchive handled hardlink archive
entries of non-zero size. Combined with flaws in libarchive's file
system sandboxing, this issue could cause an application using
libarchive to overwrite arbitrary files with arbitrary data from the
archive. (CVE-2016-5418)

Multiple out-of-bounds write flaws were found in libarchive. Specially
crafted ZIP, 7ZIP, or RAR files could cause a heap overflow,
potentially allowing code execution in the context of the application
using libarchive. (CVE-2016-1541 , CVE-2016-4300 , CVE-2016-4302)

Multiple out-of-bounds read flaws were found in libarchive. Specially
crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR files could cause the
application to read data out of bounds, potentially disclosing a small
amount of application memory, or causing an application crash.
(CVE-2015-8919 , CVE-2015-8920 , CVE-2015-8921 , CVE-2015-8923 ,
CVE-2015-8924 , CVE-2015-8925 , CVE-2015-8926 , CVE-2015-8928 ,
CVE-2015-8934)

Multiple NULL pointer dereference flaws were found in libarchive.
Specially crafted RAR, CAB, or 7ZIP files could cause an application
using libarchive to crash. (CVE-2015-8916 , CVE-2015-8917 ,
CVE-2015-8922)

Multiple infinite loop / resource exhaustion flaws were found in
libarchive. Specially crafted GZIP or ISO files could cause the
application to consume an excessive amount of resources, eventually
leading to a crash on memory exhaustion. (CVE-2016-7166 ,
CVE-2015-8930)

A denial of service vulnerability was found in libarchive. A specially
crafted CPIO archive containing a symbolic link to a large target path
could cause memory allocation to fail, causing an application using
libarchive that attempted to view or extract such archive to crash.
(CVE-2016-4809)

An integer overflow flaw, leading to a buffer overflow, was found in
libarchive's construction of ISO9660 volumes. Attempting to create an
ISO9660 volume with 2 GB or 4 GB file names could cause the
application to attempt to allocate 20 GB of memory. If this were to
succeed, it could lead to an out of bounds write on the heap and
potential code execution. (CVE-2016-6250)

Multiple instances of undefined behavior due to arithmetic overflow
were found in libarchive. Specially crafted MTREE archives, Compress
streams, or ISO9660 volumes could potentially cause the application to
fail to read the archive, or to crash. (CVE-2015-8931 , CVE-2015-8932
, CVE-2016-5844)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-743.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libarchive' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"bsdcpio-3.1.2-10.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bsdtar-3.1.2-10.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libarchive-3.1.2-10.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libarchive-debuginfo-3.1.2-10.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libarchive-devel-3.1.2-10.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdcpio / bsdtar / libarchive / libarchive-debuginfo / etc");
}
