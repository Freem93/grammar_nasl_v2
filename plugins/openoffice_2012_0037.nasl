#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58727);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2012-0037");
  script_bugtraq_id(52681);
  script_osvdb_id(80307);

  script_name(english:"OpenOffice XML External Entity RDF Document Handling Information Disclosure");
  script_summary(english:"Checks if patch is installed");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application affected by a data leakage
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of OpenOffice.org that has flaws
in the way certain XML components are processed for external entities
in ODF documents. These flaws can be utilized to access and inject the
content of local files into an ODF document without a user's knowledge
or permission, or inject arbitrary code that would be executed when
opened by the user.");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2012-0037.html");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to 340m1(Build:9589) or apply the patch referenced in
the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/OpenOffice/Build", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("global_settings.inc");

build = get_kb_item_or_exit("SMB/OpenOffice/Build");
path = get_kb_item_or_exit("SMB/OpenOffice/Path");

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) exit(1, "Failed to extract the build number from '"+build+"'.");

buildid = int(matches[2]);
if (buildid >= 9589)  exit(0, "Build " + buildid + " is not affected.");


get_kb_item_or_exit('SMB/Registry/Enumerated');
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# check for patched file
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\program\unordfmi.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "'"+(share-'$')+":"+dll+"' does not exist.");
}

filever = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(filever)) exit(1, "Unable to get file version for '"+(share-'$')+":"+dll+"'.");

if (ver_compare(ver:filever, fix:"3.3.9567.500", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + build +
             '\n  Fixed version     : 340m1(Build:9589)' +
             '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The file version of '"+(share-'$')+":"+dll+"' indicates it's been patched.");
