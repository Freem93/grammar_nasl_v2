#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-251.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71268);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2012-2392", "CVE-2012-3825", "CVE-2012-4285", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-6056", "CVE-2012-6059", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062", "CVE-2013-3557", "CVE-2013-3559", "CVE-2013-3561", "CVE-2013-4081", "CVE-2013-4083", "CVE-2013-4927", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-4936", "CVE-2013-5721");
  script_xref(name:"ALAS", value:"2013-251");
  script_xref(name:"RHSA", value:"2013:1569");

  script_name(english:"Amazon Linux AMI : wireshark (ALAS-2013-251)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2013-3559 , CVE-2013-4083)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2012-2392 ,
CVE-2012-3825 , CVE-2012-4285 , CVE-2012-4288 , CVE-2012-4289 ,
CVE-2012-4290 , CVE-2012-4291 , CVE-2012-4292 , CVE-2012-5595 ,
CVE-2012-5597 , CVE-2012-5598 , CVE-2012-5599 , CVE-2012-5600 ,
CVE-2012-6056 , CVE-2012-6059 , CVE-2012-6060 , CVE-2012-6061 ,
CVE-2012-6062 , CVE-2013-3557 , CVE-2013-3561 , CVE-2013-4081 ,
CVE-2013-4927 , CVE-2013-4931 , CVE-2013-4932 , CVE-2013-4933 ,
CVE-2013-4934 , CVE-2013-4935 , CVE-2013-4936 , CVE-2013-5721)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-251.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update wireshark' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"ALA", reference:"wireshark-1.8.10-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"wireshark-debuginfo-1.8.10-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"wireshark-devel-1.8.10-4.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel");
}
