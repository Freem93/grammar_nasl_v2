#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76709);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id("CVE-2014-4249");
  script_bugtraq_id(68605);
  script_osvdb_id(109086);

  script_name(english:"Oracle BI Publisher Mobile Service Unspecified Remote Information Disclosure (July 2014 CPU)");
  script_summary(english:"Checks for a patched file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified remote information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Business Intelligence Publisher install is affected
by an unspecified information disclosure vulnerability related to the
'Mobile Service' component.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");
include("byte_func.inc");
include("bsal.inc");
include("zip.inc");

appname = "Oracle Business Intelligence Publisher";

get_kb_item_or_exit("installed_sw/" + appname);

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

installs = get_installs(app_name:appname);

if (installs[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, appname);

report = '';

install = branch(installs[1]);

path = install['path'];
version = install['version'];

if (version !~ "^11\.1\.1\.7(\.0)?$") audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);

ear_file = hotfix_append_path(path:path, value:"bifoundation\jee\bimad.ear");

share = ereg_replace(string:ear_file, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:ear_file, pattern:"^[A-Za-z]:(.*)", replace:"\1");
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:path,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# only installs with mobile app developer will have this file
if (!fh)
{
  NetUseDel();
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
}

res = zip_parse(smb:fh);

# cleanup
CloseFile(handle:fh);
NetUseDel();

if (isnull(res)) exit(1, "Unable to parse '" + ear_file + "'.");

ts = res['files']['bimad.war']['timestamp'];

if (!ts) exit(1, "Unable to obtain timestamp of 'bimad.war' inside '" + ear_file + "'.");

item = eregmatch(pattern:"^(\d{4}-\d{2}-\d{2}) ", string:ts);
if (isnull(item) || isnull(item[1])) exit(1, "Unexpected error parsing timestamp '" + ts + "'");

fix_ts = "2014-05-31";
if (
  ver_compare(ver:str_replace(find:"-", replace:".", string:item[1]),
               fix:str_replace(find:"-", replace:".", string:fix_ts),
               strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Unpatched File        : ' + ear_file +
             '\n  \'bimad.war\' timestamp : ' + ts +
             '\n  Fixed timestamp       : ' + fix_ts + '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
