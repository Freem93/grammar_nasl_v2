#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:141. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37401);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(28123, 29903, 30036);
  script_xref(name:"MDVSA", value:"2008:141");

  script_name(english:"Mandriva Linux Security Advisory : ruby (MDVSA-2008:141)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in the Ruby interpreter and
in Webrick, the webserver bundled with Ruby.

Directory traversal vulnerability in WEBrick in Ruby 1.8 before
1.8.5-p115 and 1.8.6-p114, and 1.9 through 1.9.0-1, when running on
systems that support backslash () path separators or case-insensitive
file names, allows remote attackers to access arbitrary files via (1)
..%5c (encoded backslash) sequences or (2) filenames that match
patterns in the :NondisclosureName option. (CVE-2008-1145)

Directory traversal vulnerability in WEBrick in Ruby 1.9.0 and
earlier, when using NTFS or FAT filesystems, allows remote attackers
to read arbitrary CGI files via a trailing (1) + (plus), (2) %2b
(encoded plus), (3) . (dot), (4) %2e (encoded dot), or (5) %20
(encoded space) character in the URI, possibly related to the
WEBrick::HTTPServlet::FileHandler and WEBrick::HTTPServer.new
functionality and the :DocumentRoot option. (CVE-2008-1891)

Multiple integer overflows in the rb_str_buf_append function in Ruby
1.8.4 and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230,
1.8.7 before 1.8.7-p22, and 1.9.0 before 1.9.0-2 allow
context-dependent attackers to execute arbitrary code or cause a
denial of service via unknown vectors that trigger memory corruption.
(CVE-2008-2662)

Multiple integer overflows in the rb_ary_store function in Ruby 1.8.4
and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230, and
1.8.7 before 1.8.7-p22 allow context-dependent attackers to execute
arbitrary code or cause a denial of service via unknown vectors.
(CVE-2008-2663)

The rb_str_format function in Ruby 1.8.4 and earlier, 1.8.5 before
1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7 before 1.8.7-p22, and 1.9.0
before 1.9.0-2 allows context-dependent attackers to trigger memory
corruption via unspecified vectors related to alloca. (CVE-2008-2664)

Integer overflow in the rb_ary_splice function in Ruby 1.8.4 and
earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230, and 1.8.7
before 1.8.7-p22 allows context-dependent attackers to trigger memory
corruption via unspecified vectors, aka the REALLOC_N variant.
(CVE-2008-2725)

Integer overflow in the rb_ary_splice function in Ruby 1.8.4 and
earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7
before 1.8.7-p22, and 1.9.0 before 1.9.0-2 allows context-dependent
attackers to trigger memory corruption, aka the beg + rlen issue.
(CVE-2008-2726)

Integer overflow in the rb_ary_fill function in array.c in Ruby before
revision 17756 allows context-dependent attackers to cause a denial of
service (crash) or possibly have unspecified other impact via a call
to the Array#fill method with a start (aka beg) argument greater than
ARY_MAX_SIZE. (CVE-2008-2376)

The updated packages have been patched to fix these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2007.1", reference:"ruby-1.8.5-5.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-devel-1.8.5-5.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-doc-1.8.5-5.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-tk-1.8.5-5.2mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"ruby-1.8.6-5.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-devel-1.8.6-5.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-doc-1.8.6-5.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-tk-1.8.6-5.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
