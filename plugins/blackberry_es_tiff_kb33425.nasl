#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65643);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2012-2088", "CVE-2012-4447");
  script_bugtraq_id(54270, 55673);
  script_osvdb_id(83628, 86548);
  script_xref(name:"IAVA", value:"2013-A-0048");

  script_name(english:"BlackBerry Enterprise Server TIFF Image Processing Vulnerabilities (KB33425)");
  script_summary(english:"Checks version of image.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
reportedly contains multiple remote code execution vulnerabilities in
its image processing library :

  - The 'TIFFReadDirectory()' function in 'tif_dirread.c'
    is affected by a buffer overflow vulnerability that can
    be triggered via a specially crafted TIFF image,
    potentially leading to arbitrary code execution.
    (CVE-2012-2088)

  - A flaw in handling PixarLog compressed TIFF images may
    be triggered via a specially crafted TIFF image,
    potentially leading to arbitrary code execution.
    (CVE-2012-4447)");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB33425");
  # http://docs.blackberry.com/en/admin/deliverables/50573/BlackBerry_Enterprise_Server_February_12_2013_Interim_Security_Update-Release_Notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c3b6747");

  script_set_attribute(attribute:"solution", value:
"Install the Interim Security Software Update for February 12th 2013,
or upgrade to at least 5.0.4 MR1 for Novell GroupWise / 5.0.4 MR1 for
IBM Lotus Domino / 5.0.4 MR1 for Microsoft Exchange.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "lotus_domino_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

global_var prod, version;

function is_vuln()
{
  local_var matches, mr;

  # Decide whether the installed version is vulnerable.
  # The vulnerable versions are:
  #   BES for Microsoft Exchange : 5.0 SP2, SP3, and SP4
  #   BES for IBM Lotus Domino   : 5.0 SP2, SP3, and SP4
  #   BES for Novell GroupWise   : 5.0 SP1, SP4
  #
  #   BES Express for Microsoft Exchange : 5.0 SP2, SP3, and SP4
  #   BES Express for IBM Lotus Domino   : 5.0 SP2, SP3, and SP4
  #
  #   BES for MDS Applications : 4.1 SP3

  # And the versions that include the fix are:
  #   BES for Microsoft Exchange : 5.0 SP4 MR1
  #   BES for IBM Lotus Domino   : 5.0 SP4 MR1
  #   BES for Novell GroupWise   : 5.0 SP4 MR1

  mr = "(?: MR ([0-9]+))?( |$)";

  # Ignore anything that isn't BES.
  if ("Enterprise Server" >!< prod) return FALSE;

  if ("Microsoft Exchange" >< prod || "IBM Lotus Domino" >< prod)
  {
    # 5.0 SP2 through 5.0 SP4
    matches = eregmatch(string:version, pattern:"^5\.0\.([2-4])" + mr);

    # 5.0 SP4 MR1 fixes the issue, even though it is no longer available
    # and has been replaced by MR2
    if (
      isnull(matches) ||
      (matches[1] == 4 && !isnull(matches[2]) && matches[2] >= 1)
    ) return FALSE;

    return TRUE;
  }

  if ("Novell GroupWise" >< prod)
  {
    # 5.0 SP1 & 5.0 SP4 is vulnerable.
    matches = eregmatch(string:version, pattern:"^5\.0\.([14])" + mr);

    # 5.0 SP4 with MR1 fixes the issue
    if (
      isnull(matches) ||
      (matches[1] == 4 && !isnull(matches[2]) && matches[2] >= 1)
    ) return FALSE;

    return TRUE;
  }

  if("MDS Applications" >< prod)
  {
    # 4.1 SP3 is vulnerable.
    matches = eregmatch(string:version, pattern:"^4\.1\.3" + mr);

    if (isnull(matches)) return FALSE;

    return TRUE;
  }
  exit(0, prod + " is not on a recognized platform.");
}

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");

if (!is_vuln()) audit(AUDIT_INST_VER_NOT_VULN, prod, version);

# The vulnerable DLL can appear in two separate places:
#   1) In the BlackBerry MDS Connection Service instance
#   2) In the BlackBerry Messaging Agent instance
base = get_kb_item_or_exit("BlackBerry_ES/Path");
paths = make_list(base + "\MDS\bin");
if ("IBM Lotus Domino" >< prod)
{
  # For Lotus Domino, one of the DLLs is installed outside of the BES
  # tree.
  base = get_kb_item_or_exit("SMB/Domino/Path");
}
paths = make_list(paths, base);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

report = "";
fix = "1.3.0.43";
file = "\image.dll";

foreach path (paths)
{
  # Split the software's location into components.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dir = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1");

  # Connect to the share software is installed on.
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:dir + file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) continue;

  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  if (isnull(ver))
  {
    NetUseDel();
    audit(AUDIT_VER_FAIL, path + file);
  }

  ver = join(ver, sep:".");
  if (ver_compare(ver:ver, fix:fix) < 0)
  {
    report +=
      '\nThe following instance of image.dll needs to be updated.' +
      '\n' +
      '\n  File name         : ' + path + file +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
  NetUseDel(close:FALSE);
}

# Clean up.
NetUseDel();

# Check if fix is installed.
if (report == "")
  exit(0, prod + " " + version + " on the remote host has been patched and is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Product              : ' + prod +
    '\n  Path                 : ' + base +
    '\n  Installed version    : ' + version +
    '\n' +
    report;
  security_hole(port:port, extra:report);
}
else security_hole(port);
