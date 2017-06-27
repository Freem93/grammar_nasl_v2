#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41301);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:21:38 $");

  script_cve_id("CVE-2009-0688");

  script_name(english:"SuSE9 Security Update : cyrus-sasl (YOU Patch Number 12419)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of cyrus-sasl improves the output of function
sasl_encode64() by appending a 0 for string termination. The impact
depends on the application that uses sasl_encode64(). (CVE-2009-0688)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0688.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12419.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-crammd5-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-devel-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-digestmd5-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-gssapi-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-otp-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"cyrus-sasl-plain-2.1.18-33.14")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"cyrus-sasl-32bit-9-200905141649")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"cyrus-sasl-devel-32bit-9-200905141649")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
