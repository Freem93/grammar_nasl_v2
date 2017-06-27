#TRUSTED 1f8f4c11c92e6882da87fe343b91687f751ee9ffddd70611d4baf91e3368d694f1056fc03a028f7cde64e110df0ed4e2d7485dd905f607035c9b50a287043e5641b1ea445fdee2c56a6b776dab5fb154ae28f86e262d3a7b43f78c49a7b6d3cff56305f6b44b6bb6e811dc926343705be64e5be980584cb2f89175b6c2e04852039639315b65e2e46da80e3bce91c0b35216fd7e2075731fe62a9f603617ed04d7751d2f34dcc9a57441f134c5b110ecb71c093ad2b0872a84e788786ce9cc2462f8582554bb77091cdf7916d5674d684724149907bb711be83c33b0692f7d80e5363d32c5cedc36401e2656111761f2311f57488ead201accb82468499419f55ebfe04520304391e2b45b98a5dccc473382164a2a69cb7a094cd51cdb2d2a3e320ee133bb00daff17397ad0fb263fc277c609cb3e27c35ada26fe73fb4298c6132d2826b524065a68cbc810a9880aabfd6169acd14a5f70a0e5a371beed038a5201c44b45b96e3d0814eb819eaa290c7a842f3c082f642be3efbed4a66299c038973e783371cae740617043194208c20ae6de8711242e0399175125d9f7801efadbc3245155413d335099dfb87426f98b24b777ca0c3bfc563ea4b00c08351ff384a14ec4bbb24420cd85e37e33f78aa0e20b736c1105754bd2a2c8f862fa77421a43ff6d03fdf3b7f2edfd2c0577d4a35096dafd4375e62f5c8818436edadd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95479);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/05");

  script_cve_id("CVE-2016-6462", "CVE-2016-6463");
  script_bugtraq_id(94360, 94363);
  script_osvdb_id(147432, 147433);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva13456");
  script_xref(name:"IAVA", value:"2016-A-0329");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa1");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz85823");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-esa2");

  script_name(english:"Cisco AsyncOS for Email Security Appliances MIME Header Processing Filter Bypass (cisco-sa-20161116-esa1 / cisco-sa-20161116-esa2)");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security
appliance running on the remote host is affected by an email filter
bypass vulnerability in the AsyncOS software due to improper error
handling when processing malformed Multipurpose Internet Mail
Extension (MIME) headers that are present in an attachment. An
unauthenticated, remote attacker can exploit this vulnerability, via
email having a specially crafted MIME-encoded attached file, to bypass
the Advanced Malware Protection (AMP) filter configuration. Note that
in order to exploit this vulnerability, the AMP feature must be
configured to scan incoming email attachments.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af6ae40f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d58db7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisories
cisco-sa-20161116-esa1 or cisco-sa-20161116-esa2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

ver_fixes = make_array(
  # affected ,  # fixed
  "9.7.0.125",  "9.7.2-131",
  "9.7.1.066",  "9.7.2-131",
  "10.0.0.082", "10.0.0-203",
  "10.0.0.125", "10.0.0-203"
);

vuln = FALSE;
display_fix = NULL;
foreach affected (keys(ver_fixes))
{
  if (ver == affected)
  {
    display_fix = ver_fixes[affected];
    vuln = TRUE;
    break;
  }
}

if (isnull(display_fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

override = FALSE;
# If local checks are enabled, confirm whether AMP is configured to
# scan incoming email attachments. If local checks not enabled, only
# report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/ampconfig", "ampconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"File Reputation: Enabled", string:buf))
    vuln = TRUE;
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (!local_checks) override = TRUE;

  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : display_ver,
    bug_id   : "CSCva13456/CSCuz85823",
    fix      : display_fix,
    cmds     : make_list("ampconfig")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);
