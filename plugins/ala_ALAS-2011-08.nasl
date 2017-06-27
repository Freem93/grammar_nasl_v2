#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-08.
#

include("compat.inc");

if (description)
{
  script_id(69567);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-3256");
  script_xref(name:"ALAS", value:"2011-08");
  script_xref(name:"RHSA", value:"2011:1402");

  script_name(english:"Amazon Linux AMI : freetype (ALAS-2011-08)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MITRE CVE database describes CVE-2011-3256 as :

FreeType 2 before 2.4.7, as used in CoreGraphics in Apple iOS before
5, Mandriva Enterprise Server 5, and possibly other products, allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption) via a crafted font, a different
vulnerability than CVE-2011-0226."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-8.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum upgrade freetype' to upgrade your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freetype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/31");
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
if (rpm_check(release:"ALA", reference:"freetype-2.3.11-6.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"freetype-debuginfo-2.3.11-6.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"freetype-demos-2.3.11-6.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"freetype-devel-2.3.11-6.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-debuginfo / freetype-demos / freetype-devel");
}
