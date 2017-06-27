#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82620);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id(
    "CVE-2015-2757",
    "CVE-2015-2758",
    "CVE-2015-2759",
    "CVE-2015-2760"
  );
  script_bugtraq_id(73193, 73397, 73399, 73403);
  script_osvdb_id(
    120049,
    120050,
    120051,
    120052
  );
  script_xref(name:"IAVA", value:"2015-A-0118");
  script_xref(name:"MCAFEE-SB", value:"SB10111");

  script_name(english:"McAfee ePO DLPe Extension < 9.3.416.4 Multiple Vulnerabilities (SB10111)");
  script_summary(english:"Checks the version of the McAfee DLPe ePO extension.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote McAfee ePO server has a version of the McAfee Data Loss
Protection Endpoint (DLPe) installed that is affected by multiple
vulnerabilities :

  - The ePO extension is affected by an unspecified denial
    of service vulnerability via a database lock or license
    corruption, which can be exploited by an authenticated,
    remote attacker. (CVE-2015-2757)

  - An information disclosure vulnerability exists in the
    ePO extension that allows an authenticated, remote
    attacker to obtain sensitive information or modify the
    database by using a specially crafted URL.
    (CVE-2015-2758)

  - Multiple cross-site request forgery vulnerabilities
    exist in the ePO extension that allow a remote attacker
    to hijack the authentication of users, resulting in
    disclosure of sensitive information or modification of
    the database. (CVE-2015-2759)

  - An unspecified cross-site scripting vulnerability exists
    in the ePO extension, which an authenticated, remote
    attacker can exploit to inject arbitrary script or HTML.
    (CVE-2015-2760)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10111");
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/dlp-endpoint.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DLPe 9.3 Patch 4 Hotfix 16 (9.3.416.4) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/03/26");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/07");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  audit(AUDIT_NOT_INST, appname);

port = kb_smb_transport();

fix = '9.3.416.4';

if (ver_compare(ver:ext_version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + ext_path +
      '\n  Installed version : ' + ext_version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, appname, ext_version, ext_path);
