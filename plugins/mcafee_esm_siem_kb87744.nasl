#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93720);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2016-8006");
  script_osvdb_id(144402);

  script_name(english:"McAfee Security Information and Event Management 9.5.x / 9.6.x < 9.6.0.3 ESM Authentication Bypass (KB87744)");
  script_summary(english:"Checks the product version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee Security
Information and Event Management (SIEM) application installed on the
remote host is 9.5.x or 9.6.x prior to 9.6.0.3. It is, therefore,
affected by an authentication bypass vulnerability in the Enterprise
Security Manager (ESM) component due to a failure to require an
administrator password to be supplied a second time for certain
sensitive administrative commands. Likewise, GUI 'Terminal' commands
are allowed by an active logged-in administrative session without
supplying a password a second time. A local attacker who has
compromised the administrator session can exploit this issue to make
changes to other SIEM user information, such as user passwords.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB87744");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee SIEM version 9.6.0 MR3 (9.6.0.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_enterprise_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_esm_siem_detect.nbin");
  script_require_keys("Host/McAfee ESM/Display Version", "Host/McAfee ESM/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "McAfee Enterprise Security Manager";
version  = get_kb_item("Host/McAfee ESM/Version");
if(empty_or_null(version)) audit(AUDIT_NOT_INST, appname);
else if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, appname);
display_version  = get_kb_item_or_exit("Host/McAfee ESM/Display Version");
report = "";

if(version =~ "^9\.[56]([^0-9]|$)" && ver_compare(ver:version, fix:"9.6.0.3", strict:FALSE) < 0)
{
  fix = "9.6.0 MR3";

  report += '\n  Installed Version : ' + display_version +
            '\n  Fixed Version     : ' + fix + '\n\n';

    security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "McAfee Enterprise Security Manager", display_version);
