#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64246);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2012-5674");
  script_bugtraq_id(56590);
  script_osvdb_id(87555);

  script_name(english:"Adobe ColdFusion 10 on IIS Unspecified DoS (APSB12-25) (credentialed check)");
  script_summary(english:"Checks for hotfix files");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web-based application running on the remote Windows host is affected
by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of ColdFusion that is
affected by an unspecified denial of service. When used with Microsoft
IIS, ColdFusion 10 is vulnerable to unspecified denial of service
attacks. This vulnerability was introduced in ColdFusion 10 Update 1."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-25.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e12f147");
  script_set_attribute(attribute:"solution", value:"Upgrade to ColdFusion 10 Update 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("coldfusion_win.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

global_var errors;
errors = make_list();

##
# Checks if the given ColdFusion 10 instance is configured
# to use IIS.  This technique only works for ColdFusion 10,
# figuring out how to do this for other versions would need
# to be researched further.
#
# @anonparam instance instance name of the ColdFusion 10 instance to check
# @return TRUE if 'instance' is configured to use IIS,
#         FALSE otherwise
##
function _iis_connector_used()
{
  local_var instance, share, cfroot, dirs, i, wsconfig_path, wsconfig, lines, line;
  instance = _FCT_ANON_ARGS[0];

  cfroot = get_kb_item('SMB/coldfusion/' + instance + '/cfroot');
  if (isnull(cfroot)) return FALSE; # defensive coding - this data should always exist
  if (cfroot[strlen(cfroot) - 1] != "\") cfroot += "\";
  share = cfroot[0] + '$';

  if (!is_accessible_share(share:share))
  {
    errors = make_list(errors, 'Unable to connect to "' + share + '".');
    return FALSE;
  }

  # the "config" directory is a level up from cfroot
  wsconfig_path = '';
  dirs = split(cfroot, sep:"\", keep:TRUE);
  for (i = 0; i < max_index(dirs) - 1; i++)
    wsconfig_path += dirs[i];
  wsconfig_path += "\config\wsconfig\wsconfig.properties";
  wsconfig = hotfix_get_file_contents(wsconfig_path);
  hotfix_check_fversion_end();

  if (wsconfig['error'] == HCF_NOENT)
  {
    # if the file doesn't exist that means it's not using any connectors
    # e.g., only the built-in development server is being used. for the
    # purposes of this plugin, this isn't considered an error/unexpected
    return FALSE;
  }
  else if (wsconfig['error'] != HCF_OK)
  {
    errors = make_list(errors, 'Error reading ' + wsconfig_path + '.');
    return FALSE;
  }

  lines = split(wsconfig['data'], sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    if (line =~ '^ *[0-9]+=IIS')
      return TRUE;
  }

  return FALSE;
}

versions = make_list('10.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails
instance_info = make_list();

foreach name (keys(instances))
{
  # the bug was introduced in update 1 and fixed in update 5. if there
  # are no updates installed, the instance isn't vulnerable
  chfs = get_kb_list('SMB/coldfusion/' + name + '/chf');
  if (isnull(chfs)) continue;

  info = check_jar_chf(name, 5);
  if (!isnull(info))
  {
    # if the CF10 instance is running with a vulnerable hotfix, make
    # sure it is configured to use IIS
    if (_iis_connector_used(name))
      instance_info = make_list(instance_info, info);
  }
}

if (max_index(instance_info) == 0)
{
  if (max_index(errors) == 0)
    exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");
  else
    exit(1, join(errors, sep:' '));
}

port   = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
