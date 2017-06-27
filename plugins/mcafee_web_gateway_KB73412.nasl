#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76119);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_bugtraq_id(50341);
  script_osvdb_id(76585);

  script_name(english:"McAfee Web Gateway < 7.1.0.5 / 7.1.5.2 XSS");
  script_summary(english:"Checks version of MWG");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Web Gateway (MWG) prior to
7.1.0.5 / 7.1.5.2. It is, therefore, reportedly affected by an
unspecified cross-site scripting vulnerability in the web UI.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB73412");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7.1.0.5 / 7.1.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_web_gateway_detect.nbin");
  script_require_keys("Host/McAfee Web Gateway/Version", "Host/McAfee Web Gateway/Display Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Web Gateway";
version = get_kb_item_or_exit("Host/McAfee Web Gateway/Version");
version_display = get_kb_item_or_exit("Host/McAfee Web Gateway/Display Version");
fix = NULL;

if (version =~ "^7\.1\.0\.")
{
  fix = "7.1.0.5";
  fix_display = "7.1.0.5 Build 12054";
}
else if (version =~ "^7\.1\.5\.")
{
  fix = "7.1.5.2";
  fix_display = "7.1.5.2 Build 11970";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version_display +
      '\n  Fixed version     : ' + fix_display +
      '\n';
      security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_display);
