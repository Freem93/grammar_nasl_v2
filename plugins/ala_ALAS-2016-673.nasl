#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-673.
#

include("compat.inc");

if (description)
{
  script_id(90155);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2013-5588", "CVE-2013-5589", "CVE-2014-5025", "CVE-2014-5026", "CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454", "CVE-2015-4634", "CVE-2015-8377", "CVE-2015-8604");
  script_xref(name:"ALAS", value:"2016-673");

  script_name(english:"Amazon Linux AMI : cacti (ALAS-2016-673)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various cross-site scripting (XSS) flaws (CVE-2013-5588 ,
CVE-2014-5025 , CVE-2014-5026) and various SQL injection flaws
(CVE-2013-5589 , CVE-2015-4342 , CVE-2015-4634 , CVE-2015-8377 ,
CVE-2015-8604) were discovered affecting versions of Cacti prior to
0.8.8g.

Cross-site scripting (XSS) vulnerability in Cacti before 0.8.8d allows
remote attackers to inject arbitrary web script or HTML via
unspecified vectors. (CVE-2015-2665)

SQL injection vulnerability in the get_hash_graph_template function in
lib/functions.php in Cacti before 0.8.8d allows remote attackers to
execute arbitrary SQL commands via the graph_template_id parameter to
graph_templates.php. (CVE-2015-4454)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-673.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update cacti' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");
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
if (rpm_check(release:"ALA", reference:"cacti-0.8.8g-7.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti");
}
