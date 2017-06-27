#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73833);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"MCAFEE-SB", value:"SB10071");
  
  script_name(english:"McAfee ePolicy Orchestrator OpenSSL Information Disclosure (SB10071) (Heartbleed)");
  script_summary(english:"Checks version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator
that is affected by an information disclosure due to a flaw in the
OpenSSL library, commonly known as the Heartbleed bug. An attacker
could potentially exploit this vulnerability repeatedly to read up to
64KB of memory from the device.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10071");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Apply Hotfix 960279 per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "McAfee ePolicy Orchestrator";
version = get_kb_item_or_exit("SMB/mcafee_epo/ver");
install_path = get_kb_item_or_exit("SMB/mcafee_epo/Path");

hotfix = 'Hotfix 960279';
hotfix_file = "Apache2\bin\ssleay32.dll";
hotfix_fversion = "1.0.1.7";
min_affected = "1.0.1";

# Versions 4.6, 5.0 and 5.1 are affected.
if (version !~ "^4\.6\." && version !~ "^5\.[01]\.") audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

# Check the version of the affected DLL.
dll_path = hotfix_append_path(path:install_path, value:hotfix_file);
dll_version = hotfix_get_fversion(path:dll_path);
hotfix_handle_error(error_code:dll_version['error'], file:dll_path, appname:app_name, exit_on_fail:TRUE);
hotfix_check_fversion_end();

dll_version = join(dll_version['value'], sep:'.');

if (ver_compare(ver:dll_version, fix:min_affected, strict:FALSE) == -1) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

if (ver_compare(ver:dll_version, fix:hotfix_fversion, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  OpenSSL DLL       : ' + dll_path +
      '\n  DLL version       : ' + dll_version +
      '\n  Fixed version     : ' + hotfix_fversion +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix);
