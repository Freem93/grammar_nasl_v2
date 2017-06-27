#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64568);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/14 19:33:40 $");

  script_cve_id("CVE-2013-0472");
  script_bugtraq_id(57738);
  script_osvdb_id(89834);

  script_name(english:"IBM Tivoli Storage Manager Client 6.3 < 6.3.1.0 / 6.4 < 6.4.0.1 Unauthorized Access");
  script_summary(english:"Checks version of Tivoli Storage Manager Client");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Windows host is affected
by an unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager Client installed on the remote
Windows host is potentially affected by a vulnerability in the TSM
client Web GUI which allows unauthorized access from the local network
to files stored on the TSM server.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tsm_client_web_gui_unauthorized_access_vulnerability_cve_2013_04722?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1937f9b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tivoli Storage Manager Client 6.3.1.0 / 6.4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl");
  script_require_keys("SMB/Tivoli Storage Manager Client/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Version");
path = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Path");
if (!get_kb_item('SMB/Tivoli Storage Manager Client/WebGUI')) audit(AUDIT_NOT_INST, 'Tivoli Storage Manager Client Web GUI');

fix = '';
if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.1.0') < 0) fix = '6.3.1.0';
else if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.0.1') < 0) fix = '6.4.0.1';

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Tivoli Storage Manager Client', version, path);
