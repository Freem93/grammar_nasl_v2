#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90835);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/08 04:47:18 $");

  script_cve_id("CVE-2016-3969");
  script_osvdb_id(136571);
  script_xref(name:"MCAFEE-SB", value:"SB10153");
  script_xref(name:"IAVA", value:"2016-A-0117");

  script_name(english:"McAfee Email Gateway 7.6.x < 7.6.404 Blocked Email Alert XSS (SB10153)");
  script_summary(english:"Checks the MEG version.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Email Gateway (MEG) installed on the remote host
is 7.6.x prior to 7.6.404. It is, therefore, affected by a cross-site
scripting (XSS) vulnerability that is triggered when File Filtering is
enabled with the action set to 'ESERVICES:REPLACE'. This is due to a
failure to validate input passed via alerts for blocked email
attachments; attachments are displayed 'as is' without the XML or
HTML content being properly escaped. An unauthenticated, remote
attacker can exploit this, via a crafted email attachment, to execute
arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10153");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Email Gateway version 7.6.404 as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

if (version =~ "^7\.6")
{
  hotfix = "7.6.404-3328.101";
}
else
{
audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
}

if (
    hotfix >!< patches
   )
{
  port = 0;
  report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:port, xss:TRUE);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix, app_name, version);
