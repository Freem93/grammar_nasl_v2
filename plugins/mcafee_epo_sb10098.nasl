#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81422);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id(
    "CVE-2015-1616",
    "CVE-2015-1617",
    "CVE-2015-1618"
  );
  script_bugtraq_id(
    73419,
    73421,
    73422
  );
  script_osvdb_id(
    117432,
    117433,
    117434
  );
  script_xref(name:"MCAFEE-SB", value:"SB10098");

  script_name(english:"McAfee ePO DLPe Extension < 9.3.400 Multiple Vulnerabilities (SB10098)");
  script_summary(english:"Checks the version of the McAfee ePO DLPe extension.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote McAfee ePO server has a vulnerable version of McAfee Data
Loss Protection Endpoint (DLPe) extension installed that is affected
by multiple vulnerabilities :

  - An unspecified SQL injection vulnerability exists due to
    improper sanitization of user-supplied input. This
    allows an authenticated, remote attacker to inject or
    manipulate SQL queries, resulting in the disclosure of
    sensitive information. (CVE-2015-1616)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user-supplied input. This
    allows an authenticated, remote attacker to execute
    arbitrary script code in a user's browser session.
    (CVE-2015-1617)

  - An information disclosure vulnerability exists due to
    access checks not being properly enforced. A remote,
    authenticated attacker can gain access to password
    information via a specially crafted URL.
    (CVE-2015-1618)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10098");
  script_set_attribute(attribute:"solution", value:"Install or update to DLPe 9.3 Patch 4 (9.3.400).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

appname = 'McAfee ePO Extension for DLPe';
epo_path = get_kb_item_or_exit('SMB/mcafee_epo/Path'); # ePO install path

# first, figure out where the mcafee agent extension is installed
config_path = hotfix_append_path(path:epo_path, value:"Server\conf\Catalina\localhost\DATALOSS2000.xml");

xml = hotfix_get_file_contents(path:config_path);

hotfix_handle_error(error_code  : xml['error'],
                   file         : config_path,
                   appname      : appname,
                   exit_on_fail : TRUE);

data = xml['data'];

# determine where the extension is installed
match = eregmatch(string:data, pattern:'docBase="([^"]+)"');
if (!isnull(match))
{
  ext_path = match[1] - 'webapp';
  ext_path = str_replace(string:ext_path, find:'/', replace:"\");
}

if (isnull(ext_path))
{
  hotfix_check_fversion_end();
  exit(1, "Unable to extract extension path from '" + config_path + "'.");
}

# now that it has been determined where the extension is installed,
# and figure out which version it is
prop_file = hotfix_append_path(path:ext_path, value:'extension.properties');
ext_version = NULL;

prop_content = hotfix_get_file_contents(path:prop_file);

hotfix_handle_error(error_code  : prop_content['error'],
                   file         : prop_file,
                   appname      : appname,
                   exit_on_fail : TRUE);

data = prop_content['data'];

# sanity check - make sure that this extension actually is the epo extension for DLPe
if (data =~ "extension\.name\s*=\s*DATALOSS2000")
{
  match = eregmatch(string:data, pattern:"extension\.version\s*=\s*([\d.]+)");
  if (!isnull(match)) ext_version = match[1];
}

hotfix_check_fversion_end();

if (isnull(ext_version))
  audit(AUDIT_NOT_INST, 'McAfee ePO Extension for DLPe');

port = kb_smb_transport();

if (ver_compare(ver:ext_version, fix:'9.3.400', strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + ext_path +
      '\n  Installed version : ' + ext_version +
      '\n  Fixed version     : 9.3.400\n';
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, 'McAfee ePO Extension for DLPe', ext_version, ext_path);
