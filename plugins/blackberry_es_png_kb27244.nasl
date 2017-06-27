#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55819);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id(
    "CVE-2010-1205",
    "CVE-2010-2595",
    "CVE-2010-3087",
    "CVE-2011-0192",
    "CVE-2011-1167"
  );
  script_bugtraq_id(41174, 46658, 46951);
  script_osvdb_id(65852, 65969, 68274, 71256, 71257);

  script_name(english:"BlackBerry Enterprise Server PNG and TIFF Image Processing Vulnerabilities (KB27244)");
  script_summary(english:"Checks version of image.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
reportedly contains multiple remote code execution vulnerabilities in
its image processing library :

  - An unspecified error within the BlackBerry MDS
    Connection Service when processing PNG and TIFF images
    on a web page being viewed on a BlackBerry smartphone.

  - An unspecified error within the BlackBerry Messaging
    Agent when processing embedded PNG and TIFF images in
    an email sent to a BlackBerry smartphone.

When the image processing library is used on a specially crafted PNG
or TIFF image, an attacker may be able to execute arbitrary code in
the context of the BlackBerry Enterprise Server login account.");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB27244");

  script_set_attribute(attribute:"solution", value:
"Install the Interim Security Software Update for August 9th 2011, or
upgrade to at least 4.1.7 MR3 or 5.0.1 MR4 for Novell GroupWise /
5.0.3 MR3 for IBM Lotus Domino / 5.0.3 MR3 for Microsoft Exchange.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "lotus_domino_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

global_var prod, version;

function is_vuln()
{
  local_var matches, mr;

  # Decide whether the installed version is vulnerable. The KB
  # article and release notes disagree, so I went with the more
  # explicit of the two. The vulnerable versions are:
  #   BES for Microsoft Exchange : 5.0 SP1, 5.0 SP2, 5.0 SP3
  #   BES for IBM Lotus Domino   : 5.0 SP1, 5.0 SP2, 5.0 SP3
  #   BES for Novell GroupWise   : 4.1 SP7, 5.0 SP1
  #
  #   BES Express for Microsoft Exchange : 5.0 SP1, 5.0 SP2, 5.0 SP3
  #   BES Express for IBM Lotus Domino   : 5.0 SP2, 5.0 SP3
  #
  # And the versions that include the fix are:
  #   BES for Microsoft Exchange : 5.0 SP3 MR3
  #   BES for IBM Lotus Domino   : 5.0 SP3 MR3
  #   BES for Novell GroupWise   : 4.1 SP7 MR3, 5.0 SP1 MR4

  mr = "(?: MR ([0-9]+))? ";

  # Ignore anything that isn't BES.
  if ("Enterprise Server" >!< prod) return FALSE;

  if ("Microsoft Exchange" >< prod)
  {
    # 5.0 SP1, 5.0 SP2, and 5.0 SP3 are vulnerable.
    matches = eregmatch(string:version, pattern:"^5\.0\.([1-3])" + mr);

    # 5.0 SP3 MR3 fixes the issue.
    if (
      isnull(matches) ||
      (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 3)
    ) return FALSE;

    return TRUE;
  }

  if ("IBM Lotus Domino" >< prod)
  {
    if ("Express" >< prod)
    {
      # 5.0 SP2 and 5.0 SP3 are vulnerable.
      matches = eregmatch(string:version, pattern:"^5\.0\.([2-3])" + mr);

      # 5.0 SP3 MR3 fixes the issue.
      if (
        isnull(matches) ||
        (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 3)
      ) return FALSE;

      return TRUE;
    }
    else
    {
      # 5.0 SP1, 5.0 SP2, and 5.0 SP3 are vulnerable.
      matches = eregmatch(string:version, pattern:"^5\.0\.([1-3])" + mr);

      # 5.0 SP3 MR3 fixes the issue.
      if (
        isnull(matches) ||
        (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 3)
      ) return FALSE;

      return TRUE;
    }
  }

  if ("Novell GroupWise" >< prod)
  {
    if (version =~ "^4")
    {
      # 4.1 SP7 is vulnerable.
      matches = eregmatch(string:version, pattern:"^4\.1\.7" + mr);

      # 4.1 SP7 MR3 fixes the issue.
      if (
        isnull(matches) ||
        (!isnull(matches[1]) && matches[1] >= 3)
      ) return FALSE;

      return TRUE;
    }
    else
    {
      # 5.0 SP1 is vulnerable.
      matches = eregmatch(string:version, pattern:"^5\.0\.1" + mr);

      # 5.0 SP1 MR4 fixes the issue.
      if (
        isnull(matches) ||
        (!isnull(matches[1]) && matches[1] >= 4)
      ) return FALSE;

      return TRUE;
    }
  }

  exit(0, prod + " is not on a recognized platform.");
}

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");

if (!is_vuln()) exit(0, prod + " " + version + " is not vulnerable.");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

report = "";
fix = "1.3.0.34";
file = "\image.dll";

foreach path (paths)
{
  # Split the software's location into components.
  share = ereg_replace(string:path, pattern:"^([A-Za-z]):.*", replace:"\1$");
  dir = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1");
  NetUseDel(close:FALSE);

  # Connect to the share software is installed on.
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Failed to connect to " + share + " share.");
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
    exit(1, "Failed to extract version information from " + path + file + ".");

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
}

# Clean up.
NetUseDel();

# Check if fix is installed.
if (report == "")
  exit(0, prod + " " + version + " on the remote host has been fixed and is not affected.");

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
