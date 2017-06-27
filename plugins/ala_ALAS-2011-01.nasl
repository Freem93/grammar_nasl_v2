#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-01.
#

include("compat.inc");

if (description)
{
  script_id(69560);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-3192");
  script_xref(name:"ALAS", value:"2011-01");
  script_xref(name:"RHSA", value:"2011:1245");

  script_name(english:"Amazon Linux AMI : httpd (ALAS-2011-01)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MITRE CVE database describes CVE-2011-3192 as :

The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through
2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a
denial of service (memory and CPU consumption) via a Range header that
expresses multiple overlapping ranges, as exploited in the wild in
August 2011, a different vulnerability than CVE-2007-0086."
  );
  # http://lists.opensuse.org/opensuse-security-announce/2011-09/msg00006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4868d419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ubuntu.com/usn/USN-1199-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum upgrade httpd' to upgrade your system. Then run 'service
httpd restart' to restart the Apache HTTP Server."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/28");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.21-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.21-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.21-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.21-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.21-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.21-1.18.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
