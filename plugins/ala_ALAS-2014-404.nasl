#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-404.
#

include("compat.inc");

if (description)
{
  script_id(78347);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_xref(name:"ALAS", value:"2014-404");

  script_name(english:"Amazon Linux AMI : libXfont (ALAS-2014-404)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows in the (1) fs_get_reply, (2)
fs_alloc_glyphs, and (3) fs_read_extent_info functions in X.Org
libXfont before 1.4.8 and 1.4.9x before 1.4.99.901 allow remote font
servers to execute arbitrary code via a crafted xfs reply, which
triggers a buffer overflow.

Multiple buffer overflows in X.Org libXfont before 1.4.8 and 1.4.9x
before 1.4.99.901 allow remote font servers to execute arbitrary code
via a crafted xfs protocol reply to the (1) _fs_recv_conn_setup, (2)
fs_read_open_font, (3) fs_read_query_info, (4) fs_read_extent_info,
(5) fs_read_glyphs, (6) fs_read_list, or (7) fs_read_list_info
function.

Multiple integer overflows in the (1) FontFileAddEntry and (2)
lexAlias functions in X.Org libXfont before 1.4.8 and 1.4.9x before
1.4.99.901 might allow local users to gain privileges by adding a
directory with a large fonts.dir or fonts.alias file to the font path,
which triggers a heap-based buffer overflow, related to metadata."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-404.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libXfont' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
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
if (rpm_check(release:"ALA", reference:"libXfont-1.4.5-3.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfont-debuginfo-1.4.5-3.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfont-devel-1.4.5-3.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont / libXfont-debuginfo / libXfont-devel");
}
