#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72090);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_name(english:"ColdFusion Extended Support Version Detection");
  script_summary(english:"Checks if any ColdFusion installs require long-term support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more versions of ColdFusion that
require long-term support.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one installation of
ColdFusion on the remote host that is potentially under Extended
Support. 

Note that the Extended Support program requires a vendor contract. 
Extended Support provides upgrades and security fixes for two years
after regular support ends.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html#sort-a");
  # http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59405f25");
  script_set_attribute(attribute:"solution", value:
"Ensure that the host subscribes to Adobe's Extended Support program
for ColdFusion and continues to receive security updates.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_unsupported.nasl");
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

info = make_array();

extended_support_installs = get_kb_list_or_exit("www/coldfusion/extended_support/*");

if (extended_support_installs)
{
  foreach path_ver (keys(extended_support_installs))
  {
    temp_info = NULL;
    pv = path_ver - "www/coldfusion/extended_support/";
    # pv should now have:
    # {www-dir}/{version}/{port}
    pieces = eregmatch(string:pv, pattern:"^(.*)/([0-9._]+)/([0-9]+)$");
    if (pieces)
    {
      dir = str_replace(string:pieces[1], find:"\", replace:"/");
      version = pieces[2];
      port = pieces[3];

      temp_info =
        '\n  URL           : ' + build_url(port:port, qs:dir) +
        '\n  Version       : ' + version +
        '\n  Support dates : ' + extended_support_installs[path_ver];

      if (!info[port])
        info[port] = temp_info;
      else
        info[port] += temp_info;
    }
  }
}


if (max_index(keys(info)))
{
  pre_report = '\n' + 'The following '+app+' installs are in Extended Support status : \n';

  foreach port (keys(info))
  {
    if (report_verbosity > 0) security_note(port:port, extra:pre_report+info[port]);
    else security_note(port);
  }

}
else audit(AUDIT_NOT_INST, app + " under Extended Support");
