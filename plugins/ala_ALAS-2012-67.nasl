#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-67.
#

include("compat.inc");

if (description)
{
  script_id(69674);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/09/19 13:28:21 $");

  script_cve_id("CVE-2012-0946");
  script_xref(name:"ALAS", value:"2012-67");

  script_name(english:"Amazon Linux AMI : nvidia (ALAS-2012-67)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The NVIDIA UNIX driver before 295.40 allows local users to access
arbitrary memory locations by leveraging GPU device-node read/write
privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-67.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nvidia' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nvidia-kmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nvidia-kmod-3.2.12-3.2.4.amzn1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"nvidia-295.40.3.2.12-1.1.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"nvidia-kmod-295.40.3.2.12-1.1.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"nvidia-kmod-3.2.12-3.2.4.amzn1-295.40-1.1.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nvidia / nvidia-kmod / nvidia-kmod-3.2.12-3.2.4.amzn1");
}
