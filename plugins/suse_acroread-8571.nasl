#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66506);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/27 10:42:17 $");

  script_cve_id("CVE-2013-2549", "CVE-2013-2550", "CVE-2013-2718", "CVE-2013-2719", "CVE-2013-2720", "CVE-2013-2721", "CVE-2013-2722", "CVE-2013-2723", "CVE-2013-2724", "CVE-2013-2725", "CVE-2013-2726", "CVE-2013-2727", "CVE-2013-2729", "CVE-2013-2730", "CVE-2013-2731", "CVE-2013-2732", "CVE-2013-2733", "CVE-2013-2734", "CVE-2013-2735", "CVE-2013-2736", "CVE-2013-2737", "CVE-2013-3337", "CVE-2013-3338", "CVE-2013-3339", "CVE-2013-3340", "CVE-2013-3341", "CVE-2013-3342");

  script_name(english:"SuSE 10 Security Update : Acrobat Reader (ZYPP Patch Number 8571)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Acrobat Reader has been updated to version 9.5.5.

The Adobe Advisory can be found at:
https://www.adobe.com/support/security/bulletins/apsb13-15.html

These updates resolve

  - memory corruption vulnerabilities that could lead to
    code execution. (CVE-2013-2718 / CVE-2013-2719 /
    CVE-2013-2720 / CVE-2013-2721 / CVE-2013-2722 /
    CVE-2013-2723 / CVE-2013-2725 / CVE-2013-2726 /
    CVE-2013-2731 / CVE-2013-2732 / CVE-2013-2734 /
    CVE-2013-2735 / CVE-2013-2736 / CVE-2013-3337 /
    CVE-2013-3338 / CVE-2013-3339 / CVE-2013-3340 /
    CVE-2013-3341)

  - an integer underflow vulnerability that could lead to
    code execution. (CVE-2013-2549)

  - a use-after-free vulnerability that could lead to a
    bypass of Adobe Reader's sandbox protection.
    (CVE-2013-2550)

  - an information leakage issue involving a JavaScript API.
    (CVE-2013-2737)

  - a stack overflow vulnerability that could lead to code
    execution. (CVE-2013-2724)

  - buffer overflow vulnerabilities that could lead to code
    execution. (CVE-2013-2730 / CVE-2013-2733)

  - integer overflow vulnerabilities that could lead to code
    execution. (CVE-2013-2727 / CVE-2013-2729)

  - a flaw in the way Reader handles domains that have been
    blacklisted in the operating system. (CVE-2013-3342)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2719.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2720.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2724.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3338.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3340.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3342.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8571.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-9.5.5-0.6.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-cmaps-9.4.6-0.6.63")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-ja-9.4.6-0.6.63")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-ko-9.4.6-0.6.63")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-zh_CN-9.4.6-0.6.63")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"acroread-fonts-zh_TW-9.4.6-0.6.63")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
