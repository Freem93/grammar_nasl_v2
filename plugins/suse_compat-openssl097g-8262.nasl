#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62060);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/12 02:34:59 $");

  script_cve_id("CVE-2012-2110", "CVE-2012-2131");

  script_name(english:"SuSE 10 Security Update : compat-openssl097g (ZYPP Patch Number 8262)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This compat-openssl097g rollup update contains various security 
fixes :

  - incorrect integer conversions in OpenSSL could have
    resulted in memory corruption during buffer management
    operations. (CVE-2012-2131 / CVE-2012-2110)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2131.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8262.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"compat-openssl097g-0.9.7g-13.23.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"compat-openssl097g-32bit-0.9.7g-13.23.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"compat-openssl097g-0.9.7g-13.23.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"compat-openssl097g-32bit-0.9.7g-13.23.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
