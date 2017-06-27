#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66255);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/25 03:25:02 $");

  script_cve_id("CVE-2012-6054", "CVE-2012-6056", "CVE-2013-2478", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482", "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2488");

  script_name(english:"SuSE 10 Security Update : wireshark (ZYPP Patch Number 8500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark has been updated to 1.6.14 to fix bugs and security issues :

Vulnerabilities fixed :

  - The sFlow dissector could go into an infinite loop.
    wnpa-sec-2012-32 CVE-2012-6054: * The SCTP dissector
    could go into an infinite loop. wnpa-sec-2012-33
    CVE-2012-6056: * The MS-MMS dissector could crash.
    wnpa-sec-2013-13 CVE-2013-2478

  - The RTPS and RTPS2 dissectors could crash.
    wnpa-sec-2013-15 CVE-2013-2480: * The Mount dissector
    could crash. wnpa-sec-2013-16 CVE-2013-2481

  - The AMPQ dissector could go into an infinite loop.
    wnpa-sec-2013-17 CVE-2013-2482: * The ACN dissector
    could attempt to divide by zero. wnpa-sec-2013-18
    CVE-2013-2483: * The CIMD dissector could crash.
    wnpa-sec-2013-19 CVE-2013-2484

  - The FCSP dissector could go into an infinite loop.
    wnpa-sec-2013-20 CVE-2013-2485: * The DTLS dissector
    could crash. wnpa-sec-2013-22 CVE-2013-2488

Further bug fixes and updated protocol support are listed in :

http://www.wireshark.org/docs/relnotes/wireshark-1.6.14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2488.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8500.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"wireshark-1.6.14-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-1.6.14-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-devel-1.6.14-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
