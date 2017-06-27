#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59318);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_name(english:"Windows Flamer / Skywiper Malware Detection");
  script_summary(english:"Checks for evidence of Flamer / Skywiper");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host appears to have been compromised.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus has found evidence that the
remote Windows host has been compromised by malware known as Flamer
and Skywiper.");

  script_set_attribute(attribute:"solution", value:"Restore the system from a known set of good backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"see_also", value:"http://www.crysys.hu/skywiper/skywiper.pdf");


  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

function matches(path, sig)
{
  local_var blob, chunk, fh, found, length, offset, overlap;

  # Open the file specified
  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (isnull(fh))
    return FALSE;

  # Check that the file isn't empty.
  length = GetFileSize(handle:fh);
  if (length == 0)
  {
    CloseFile(handle:fh);
    return FALSE;
  }

  # Set search parameters.
  offset = 0;
  overlap = strlen(sig) + 1;
  chunk = 10240;

  # Search for the signature in the file.
  found = FALSE;
  while (!found && offset <= length)
  {
    # Read a chunk from the file.
    blob = ReadFile(handle:fh, length:chunk, offset:offset);
    if (strlen(blob) == 0)
      break;

    # Strip out the NUL bytes.
    blob = str_replace(string:blob, find:raw_string(0), replace:" ");

    # Find the signature.
    found = (sig >< blob);

    # Advance to the next chunk.
    offset += chunk - overlap;
  }

  CloseFile(handle:fh);

  return found;
}

function find_infection()
{
  local_var i, len, path, sig;

  len = max_index(_FCT_ANON_ARGS);

  for (i = 0; i < len; i += 2)
  {
    path = _FCT_ANON_ARGS[i];
    sig = _FCT_ANON_ARGS[i + 1];

    if (matches(path:path, sig:sig))
      return path;
  }

  return FALSE;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Find where Windows was installed.
base = hotfix_get_systemroot();
if (isnull(base))
  exit(1, "Failed to determine the location of %windir%.");
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
windir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");

# Connect to the share Windows is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Find infection if it exists.
infected = find_infection(
  # This signature is "REAR_WINDOW" encoded as UTF-16LE and then XORed against
  # 0xFF.
  windir + "\system32\boot32drv.sys",
  raw_string(
    0xAD, 0xFF, 0xBA, 0xFF, 0xBE, 0xFF, 0xBB, 0xFF,
    0xA0, 0xFF, 0xA8, 0xFF, 0xB6, 0xFF, 0xB1, 0xFF,
    0xBB, 0xFF, 0xB0, 0xFF, 0xA8, 0x0A
  ),

  # This signature is an RC4-encrypted header.
  windir + "\system32\ccalc32.sys",
  raw_string(
    0xA3, 0x47, 0xDE, 0xFE, 0x8B, 0x49, 0x09, 0x34,
    0x67, 0xAE, 0xDC, 0xCF, 0xFF, 0xC5, 0x45, 0x5D
  ),

  windir + "\system32\mssecmgr.ocx",
  "Unidentified build, Aug 31 2011 23:15:32"
);

# Clean up.
NetUseDel();

if (!infected)
  exit(0, "No evidence of Flamer / Skywiper was found on the remote host.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nThe following file was found on the remote host, and is indicative of' +
    '\na Flamer / Skywiper infection :' +
    '\n' +
    '\n  '+base + infected +
    '\n';
}

security_hole(port:port, extra:report);
