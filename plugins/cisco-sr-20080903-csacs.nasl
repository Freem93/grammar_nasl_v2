#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69134);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2008-2441");
  script_bugtraq_id(30997);
  script_osvdb_id(47917);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsq10103");
  script_xref(name:"CISCO-SR", value:"cisco-sr-20080903-csacs");

  script_name(english:"Cisco Secure ACS EAP Parsing Vulnerability (cisco-sr-20080903-csacs)");
  script_summary(english:"Checks ACS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host has a memory corruption vulnerability.  The length of
EAP-Response packets is not properly parsed.  Remote code execution
could be possible, but has not been confirmed.  A remote,
unauthenticated attacker could exploit this to execute arbitrary code."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20080903-csacs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00d5491a");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Sep/33");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the relevant Cisco Secure Access Control System version
referenced in Cisco Security Response cisco-sr-20080903-csacs."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_acs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

if (ver =~ "^3\.")
  fix = '3.3.4.12.8';
else if (ver =~ "^4\.0\.")
  fix = 'n/a (contact Cisco)';
else if (ver =~ "^4\.1\.")
  fix = '4.1.4.13.11';
else if (ver =~ "^4\.2\.")
  fix = '4.2.0.124.4';
else
  fix = NULL; # the software is no vulnerable, no fix is needed

if (
  isnull(fix) ||
  ('n/a' >!< fix && ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
)
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

