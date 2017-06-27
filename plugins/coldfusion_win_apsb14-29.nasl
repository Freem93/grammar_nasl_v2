#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79859);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-9166");
  script_bugtraq_id(71569);
  script_osvdb_id(115565);

  script_name(english:"Adobe ColdFusion Unspecified DoS (APSB14-29) (credentialed check)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host
is affected by an unspecified denial of service vulnerability due to a
resource consumption issue.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb14-29.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in Adobe advisory APSB14-29.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

versions = make_list('10.0.0', '11.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

# a connection needs to be made to the system in order to call check_cfide_hotfix()
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 15);
  }
  else if (ver == "11.0.0")
  {
    info = check_jar_chf(name,3);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0) exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
