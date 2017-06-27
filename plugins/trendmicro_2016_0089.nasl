#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91428);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    138488,
    138489,
    138490
  );

  script_name(english:"Trend Micro Titanium Security 8.x < 8.0.2063 / 10.x < 10.0.1265 Multiple Vulnerabilities");
  script_summary(english:"Checks the Trend Micro Titanium Security version.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Trend Micro Titanium Security product installed on
the remote host is 8.x prior to 8.0.2063 or 10.x prior to 10.0.1265.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    /LocalHelp/loader script due to improper validation of
    input before returning it to users. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a crafted web page, to execute arbitrary code
    in the user's browser session. (VulnDB 138488)

  - A flaw exists in the CoreServiceShell.exe HTTP service
    due to improper sanitization of user input by the 'wtp'
    and 'loadhelp' endpoints. An unauthenticated, remote
    attacker can exploit this, by using a path traversal
    attack, to access arbitrary files with SYSTEM
    privileges. (VulnDB 138489)

  - A flaw exists in the CoreServiceShell.exe HTTP service
    when handling the 'URL' parameter to the 'continue'
    endpoint. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a crafted
    web page, to inject arbitrary headers. (VulnDB 138490)");
  # https://esupport.trendmicro.com/en-us/home/pages/technical-support/1114095.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4a513cf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Titanium Security software version 8.0.2063 or
10.0.1265");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trendmicro:titanium");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("installed_sw/Trend Micro Titanium");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

sw = "Trend Micro Titanium";
install = get_single_install(app_name:sw, exit_if_unknown_ver:TRUE);
path    = install["path"];
ver = install["version"];
app = install["Product"];
flag = FALSE;

# Check Granularity
if(ver =~ "^(8|10)(\.0)?([^0-9\.]|$)") audit(AUDIT_VER_NOT_GRANULAR, app, ver);

if(ver =~ "^8\.0\." && ver_compare(ver:ver, fix:"8.0.2063", strict:FALSE) < 0){
  flag = TRUE;
  fix = "8.0.2063";
}
else if (ver =~ "^10\.0\." && ver_compare(ver:ver, fix:"10.0.1265", strict:FALSE) < 0){
  flag = TRUE;
  fix = "10.0.1265";
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (flag)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) 
  port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xss:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
