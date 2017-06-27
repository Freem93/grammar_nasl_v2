#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70785);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2013-6349");
  script_bugtraq_id(63544);
  script_osvdb_id(98669);
  script_xref(name:"MCAFEE-SB", value:"SB10057");

  script_name(english:"McAfee Email Gateway Appliance 7.x Unspecified Command Injection (SB10057)");
  script_summary(english:"Checks version of McAfee Email Gateway");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is potentially affected by an unspecified command
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the self-reported version of the Web UI on the remote
McAfee Email Gateway appliance, it is potentially affected by an
unspecified command injection vulnerability.  Exploitation could lead to
arbitrary code execution. 

Note that Nessus has not checked for the presence of a patch so this
finding may be a false positive."
  );
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10057");
  script_set_attribute(attribute:"solution", value:"Apply MEG 7.0.4 or 7.5.1 or refer to the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_webshield_web_ui_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "www/mcafee_webshield");
  script_require_ports("Services/www", 443, 10443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:10443);

install = get_install_from_kb(appname:'mcafee_webshield', port:port, exit_on_fail:TRUE);

ver = install['ver'];
dir = install['dir'];

url = build_url(qs:dir, port:port);

if (isnull(ver) || ver == '' || ver !~ '^([0-9]|[0-9][0-9.]*[0-9])$')
  exit(0, 'No usable version information available for McAfee Email Gateway Web UI on port ' + port + '.');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# matches 7.0.0-7.0.3 and 7.5.0
if (ver =~ "^7(\.0(\.[0-3])?)?$" || ver =~ "^7(\.5(\.0)?)?$")
{
  if (report_verbosity > 0)
  {
    report =
      '\n    URL               : ' + url +
      '\n    Installed version : ' + ver +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_OS_RELEASE_NOT, "McAfee Email Gateway", "7.0 - 7.0.3 or 7.5", ver);
