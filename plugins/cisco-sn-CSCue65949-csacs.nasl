#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72141);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0668");
  script_bugtraq_id(65016);
  script_osvdb_id(102256);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue65949");

  script_name(english:"Cisco Secure ACS Portal XSS (CSCue65949)");
  script_summary(english:"Checks ACS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host is affected by a cross-site scripting (XSS) vulnerability
due to insufficient input validation of a parameter."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0668
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2cc2047");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32489");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Cisco Secure Access Control System patch referenced in Cisco
Bug Id CSCue65949."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

if (
  (ver == "5.1") ||
  (ver == "5.1.0.44") ||
  (ver == "5.2") ||
  (ver == "5.2.0.26") ||
  (ver == "5.2.0.26.1") ||
  (ver == "5.2.0.26.2") ||
  (ver == "5.2.0.26.3") ||
  (ver == "5.2.0.26.4") ||
  (ver == "5.2.0.26.5") ||
  (ver == "5.2.0.26.6") ||
  (ver == "5.2.0.26.7") ||
  (ver == "5.2.0.26.8") ||
  (ver == "5.2.0.26.9") ||
  (ver == "5.2.0.26.10") ||
  (ver == "5.2.0.26.11") ||
  (ver == "5.3") ||
  (ver == "5.3.0.6") ||
  (ver == "5.3.0.40") ||
  (ver == "5.3.0.40.1") ||
  (ver == "5.3.0.40.2") ||
  (ver == "5.3.0.40.3") ||
  (ver == "5.3.0.40.4") ||
  (ver == "5.3.0.40.5") ||
  (ver == "5.3.0.40.6") ||
  (ver == "5.3.0.40.7") ||
  (ver == "5.3.0.40.8") ||
  (ver == "5.4") ||
  (ver == "5.4.0.46.1") ||
  (ver == "5.4.0.46.2") ||
  (ver == "5.4.0.46.3")
)
{
  fix = '5.5.0.46';

  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco Secure ACS', display_ver);
