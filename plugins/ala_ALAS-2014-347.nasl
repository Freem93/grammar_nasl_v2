#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-347.
#

include("compat.inc");

if (description)
{
  script_id(78290);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-2326", "CVE-2014-2327", "CVE-2014-2328", "CVE-2014-2708", "CVE-2014-2709");
  script_xref(name:"ALAS", value:"2014-347");

  script_name(english:"Amazon Linux AMI : cacti (ALAS-2014-347)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Cross-site request forgery (CSRF) vulnerability in Cacti 0.8.7g,
0.8.8b, and earlier allows remote attackers to hijack the
authentication of users for unspecified commands, as demonstrated by
requests that (1) modify binary files, (2) modify configurations, or
(3) add arbitrary users.

Cross-site scripting (XSS) vulnerability in cdef.php in Cacti 0.8.7g,
0.8.8b, and earlier allows remote attackers to inject arbitrary web
script or HTML via unspecified vectors.

lib/rrd.php in Cacti 0.8.7g, 0.8.8b, and earlier allows remote
attackers to execute arbitrary commands via shell metacharacters in
unspecified parameters.

Multiple SQL injection vulnerabilities in graph_xport.php in Cacti
0.8.7g, 0.8.8b, and earlier allow remote attackers to execute
arbitrary SQL commands via the (1) graph_start, (2) graph_end, (3)
graph_height, (4) graph_width, (5) graph_nolegend, (6) print_source,
(7) local_graph_id, or (8) rra_id parameter.

lib/graph_export.php in Cacti 0.8.7g, 0.8.8b, and earlier allows
remote authenticated users to execute arbitrary commands via shell
metacharacters in unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-347.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update cacti' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
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
if (rpm_check(release:"ALA", reference:"cacti-0.8.8b-5.4.amzn1")) flag++;

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
