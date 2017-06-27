#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57154);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/27 17:11:05 $");

  script_cve_id("CVE-2011-1353", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");

  script_name(english:"SuSE 10 Security Update : Acrobat Reader (ZYPP Patch Number 7833)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Acrobat reader was updated to version 9.4.6 to fix several security
issues. (CVE-2011-1353 / CVE-2011-2431 / CVE-2011-2432 / CVE-2011-2433
/ CVE-2011-2434 / CVE-2011-2435 / CVE-2011-2436 / CVE-2011-2437 /
CVE-2011-2438 / CVE-2011-2439 / CVE-2011-2440 / CVE-2011-2441 /
CVE-2011-2442)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2436.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2437.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2442.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7833.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-9.4.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-cmaps-9.4.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-ja-9.4.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-ko-9.4.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-zh_CN-9.4.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-zh_TW-9.4.6-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
