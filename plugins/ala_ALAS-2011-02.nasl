#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-02.
#

include("compat.inc");

if (description)
{
  script_id(69561);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-3208");
  script_xref(name:"ALAS", value:"2011-02");
  script_xref(name:"RHSA", value:"2011:1317");

  script_name(english:"Amazon Linux AMI : cyrus-impad (ALAS-2011-02)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MITRE CVE database describes CVE-2011-3208 as :

A buffer overflow flaw was found in the cyrus-imapd NNTP server,
nntpd. A remote user able to use the nntpd service could use this flaw
to crash the nntpd child process or, possibly, execute arbitrary code
with the privileges of the cyrus user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-2.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum upgrade cyrus-imapd' to upgrade your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-imapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
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
if (rpm_check(release:"ALA", reference:"cyrus-imapd-2.3.16-6.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-imapd-debuginfo-2.3.16-6.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-imapd-devel-2.3.16-6.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cyrus-imapd-utils-2.3.16-6.4.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-debuginfo / cyrus-imapd-devel / etc");
}
