#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-13.
#

include("compat.inc");

if (description)
{
  script_id(69572);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2010-4818", "CVE-2010-4819");
  script_xref(name:"ALAS", value:"2011-13");
  script_xref(name:"RHSA", value:"2011:1359");

  script_name(english:"Amazon Linux AMI : xorg-x11-server (ALAS-2011-13)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple input sanitization flaws were found in the X.Org GLX (OpenGL
extension to the X Window System) extension. A malicious, authorized
client could use these flaws to crash the X.Org server or,
potentially, execute arbitrary code with root privileges.
(CVE-2010-4818)

An input sanitization flaw was found in the X.Org Render extension. A
malicious, authorized client could use this flaw to leak arbitrary
memory from the X.Org server process, or possibly crash the X.Org
server. (CVE-2010-4819)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update xorg-x11-server' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-source");
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
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xephyr-1.7.7-29.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xnest-1.7.7-29.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xvfb-1.7.7-29.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-common-1.7.7-29.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-debuginfo-1.7.7-29.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-source-1.7.7-29.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xephyr / xorg-x11-server-Xnest / etc");
}
