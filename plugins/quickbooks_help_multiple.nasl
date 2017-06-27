#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58848);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/04 00:44:46 $");

  script_cve_id(
    "CVE-2012-2418",
    "CVE-2012-2419",
    "CVE-2012-2420",
    "CVE-2012-2421",
    "CVE-2012-2422",
    "CVE-2012-2423",
    "CVE-2012-2424",
    "CVE-2012-2425"
  );
  script_bugtraq_id(52836, 52854);
  script_osvdb_id(80819, 80820, 81807, 81833, 81834, 81835, 81836, 81840);
  script_xref(name:"CERT", value:"232979");
  script_xref(name:"Secunia", value:"48686");

  script_name(english:"Intuit QuickBooks Help System Multiple Vulnerabilities");
  script_summary(english:"Checks if the workaround is in use");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Business accounting software installed on the remote Windows host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickBooks installed on the remote host has multiple
vulnerabilities.  Versions 2008 through 2012 have multiple
vulnerabilities in the help system that could result in information
disclosure or memory corruption.

A remote attacker could exploit these issues by tricking a user into
requesting a maliciously crafted web page, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522138");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522139");
  script_set_attribute(attribute:"see_also", value:"http://security.intuit.com/alert.php?a=43");
  script_set_attribute(
    attribute:"solution",
    value:
"Fixes are available for QuickBooks 2008 through 2012 via the
automatic update mechanism.  The presence of the patch can be
verified by checking if the digital signature of
HelpAsyncPluggableProtocol.dll has a signing date of April 27, 2012
or later.

If updating is not possible, workarounds that disable QuickBooks help
pages are available.  Refer to the researcher's advisory for more
information.  Note that deleting or renaming the affected DLL may not
be adequate under some circumstances."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intuit:quickbooks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("quickbooks_installed.nasl");
  script_require_keys("SMB/QuickBooks/Installed", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("byte_func.inc");
include("audit.inc");

# these should probably be put into an include file
ACCESS_ALLOWED_ACE_TYPE = 0;
ACCESS_DENIED_ACE_TYPE = 1;


##
# figures out the QB version based on the product name.
# For example, "QuickBooks Enterprise Solutions 10.0" becomes 2010
#
# @anonparam product_name QB product name
# @return QB year associated with 'product_name' (integer) iff 'product_name' is QB 2008 - 2012,
#         NULL otherwise
##
function _get_qb_version()
{
  local_var product_name;
  product_name = _FCT_ANON_ARGS[0];

  if ('8.0' >< product_name || '2008' >< product_name)
    return 2008;
  if ('9.0' >< product_name || '2009' >< product_name)
    return 2009;
  if ('10.0' >< product_name || '2010' >< product_name)
    return 2010;
  if ('11.0' >< product_name || '2011' >< product_name)
    return 2011;
  if ('12.0' >< product_name || '2012' >< product_name)
    return 2012;
  else
    return NULL;
}

##
# compares two UTCTime (ASN.1) values
#
# @anonparam time1 time to compare
# @anonparam time2 time to compare
#
# @return -1 if time1 < time2,
#          0 if time1 == time2,
#          1 if time1 > time2
##
function _compare_times()
{
  local_var time1, time2, i, unit1, unit2;
  time1 = _FCT_ANON_ARGS[0] - 'Z';
  time2 = _FCT_ANON_ARGS[1] - 'Z';

  # times are formatted YYMMDDHHmmSS
  # this compares the times from left to right, by unit
  for (i = 0; i < strlen(time1); i += 2)
  {
    unit1 = int(substr(time1, i, i + 1));
    unit2 = int(substr(time2, i, i + 1));

    if (unit1 < unit2)
      return -1;
    if (unit1 > unit2)
      return 1;
  }

  return 0;
}

##
# Converts an ASN.1 UTCTime into a human readable format
#
# @anonparam utctime UTCTime to convert
#
# @return human readable version of 'utctime'
#
##
function _convert_utctime()
{
  local_var utctime, year, month, day;
  utctime = _FCT_ANON_ARGS[0];

  year = substr(utctime, 0, 1);
  month = int(substr(utctime, 2, 3));
  day = int(substr(utctime, 4, 5));

  if (int(year) >= 50)
    year = '19' + year;
  else
    year = '20' + year;

  if (month == 1)
    month = 'January';
  if (month == 2)
    month = 'February';
  if (month == 3)
    month = 'March';
  if (month == 4)
    month = 'April';
  if (month == 5)
    month = 'May';
  if (month == 6)
    month = 'June';
  if (month == 7)
    month = 'July';
  if (month == 8)
    month = 'August';
  if (month == 9)
    month = 'September';
  if (month == 10)
    month = 'October';
  if (month == 11)
    month = 'November';
  if (month == 12)
    month = 'December';

  return strcat(month, ' ', day, ', ', year);
}

##
# recursively decodes pkcs7 data, attempting to extract the signing-time
#
# @anonparam data asn.1 encoded data
# @return signing time, if it was extracted from 'data',
#         NULL otherwise
##
function _get_signing_time()
{
  local_var data, pos, signing_time_start, res, tag, set, utc, signing_time;
  data = _FCT_ANON_ARGS[0];
  pos = 0;
  signing_time_start = FALSE;
  signing_time = NULL;

  while (pos < strlen(data) - 1 && isnull(signing_time))
  {
    res = der_decode(data:data, pos:pos);
    tag = res[0];
    pos = res[2];

    if (tag & 0x20) # constructed (the data contains more TLVs)
    {
      signing_time = _get_signing_time(res[1]);
      if (!isnull(signing_time))
        break;
    }

    # signing-time OID
    if (res[0] == 0x06 && der_decode_oid(oid:res[1]) == '1.2.840.113549.1.9.5')
    {
      # it appears this structure is always
      #
      # signing-time object
      #   set
      #     UTCTime <- this is the signing time data
      set = der_decode(data:data, pos:pos);
      if (set[0] & 0x20)
      {
        utc = der_decode(data:set[1], pos:0);
        if (utc[0] == 0x17)  # UTCTime
          return utc[1];
      }
    }
  }

  return signing_time;
}

##
# extracts the digital signature (pkcs7) from an exe
#
# @anonparam fh file handle of file to extract signature from
# @return 
function _get_pkcs7_sig()
{
  local_var fh, dos_header, e_lfanew, offset, sig_len, unknown, sig, data_dir_cert_offset, cert_rva;
  fh = _FCT_ANON_ARGS[0];
  dos_header = ReadFile(handle:fh, offset:0, length:64);
  e_lfanew = get_dword(blob:dos_header, pos:60);
  data_dir_cert_offset = e_lfanew + 24 + 128; # + file header + offset to cert data dir rva
  cert_rva = ReadFile(handle:fh, offset:data_dir_cert_offset, length:4);
  cert_rva = get_dword(blob:cert_rva, pos:0);
  if (cert_rva == 0)
    return NULL;

  sig_len = ReadFile(handle:fh, offset:cert_rva, length:4);
  sig_len = getdword(blob:sig_len, pos:0);
  unknown = ReadFile(handle:fh, offset:cert_rva + 4, length:4); offset += 4;  # constant (\x00\x02\x02\x00)
  sig = ReadFile(handle:fh, offset:cert_rva + 8, length:sig_len - 8);

  return sig;
}

##
# Checks if a workaround associated with changing file permissions is being used
#
# This possibly could result in false positives since it doesn't attempt to resolve
# which users belong to which groups and what everyone's effective permissions are
#
# @param dacl DACL of file to check
#
# @return TRUE if no users have execute permissions
#         FALSE otherwise
##
function _check_file_workaround()
{
  local_var dacl, everyone_denied, execute_perms, ace, rights, type, sid, execute_bit_set, execute_perm;
  dacl = _FCT_ANON_ARGS[0];
  everyone_denied = FALSE;
  execute_perms = make_array();

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace))
      continue;

    rights = ace[0];
    type = ace[3];
    sid = sid2string(sid:ace[1]);
    if (isnull(sid))
      continue;

    # an Everyone ACE that denies execute access takes precedence over everything else
    if (type == ACCESS_DENIED_ACE_TYPE && sid == '1-1-0' && rights & FILE_EXECUTE)
      return TRUE;

    if (rights & FILE_EXECUTE)
    {
      if (isnull(execute_perms[sid]) && type == ACCESS_DENIED_ACE_TYPE)
        execute_perms[sid] = FALSE;
      else if (isnull(execute_perms[sid]) && type == ACCESS_ALLOWED_ACE_TYPE)
        execute_perms[sid] = TRUE;
      else if (execute_perms[sid] && type == ACCESS_DENIED_ACE_TYPE)
        execute_perms[sid] = FALSE;
    }
  }

  # checks if there are any SIDs that have execute permissions on this file
  foreach execute_perm (execute_perms)
  {
    if (execute_perm)
      return FALSE;
  }

  return TRUE;
}

##
# Gets the DACL of the given file
#
# @anonparam fh handle of the file to obtain the DACL for
#
# @return DACL associated with 'fh'
##
function _get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
  if (isnull(sd))
    return NULL;

  dacl = sd[3];
  if (isnull(dacl))
    return NULL;

  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
    return NULL;

  return dacl;
}

appname = 'QuickBooks';
qb_installs = get_kb_list_or_exit("SMB/QuickBooks/*/path");
arch = get_kb_item_or_exit("SMB/ARCH");

if (arch == 'x64')
  key_prefix = "SOFTWARE\Wow6432Node\Classes\PROTOCOLS\Handler\intu-help-qb";
else
  key_prefix = "SOFTWARE\Classes\PROTOCOLS\Handler\intu-help-qb";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
reg_workaround_missing = make_array();

# don't check for the workaround during paranoid scans
if (report_paranoia < 2)
{
  for (i = 1; i <= 5; i++)
  {
    item = strcat(key_prefix, i, '\\CLSID');
    value = get_registry_value(handle:hklm, item:item);

    if (!isnull(value))
      reg_workaround_missing[2007 + i] = TRUE;
  }
}
RegCloseKey(handle:hklm);

if (report_paranoia < 2 && max_index(keys(reg_workaround_missing)) == 0)
{
  # if none of the keys referenced in the advisory could be opened, either a
  # non-vulnerable version of QB is being used, or a workaround is being used
  close_registry();
  exit(0, 'QuickBooks is installed and not vulnerable (a registry workaround is being used).');
}
else
{
  close_registry(close:FALSE);
}

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
affected_files = make_list();
everyone_denied = make_array();
execute_perms = make_array();
fixed_signing_time = '120427000000Z';

# if the registry workaround isn't being used, see if the vulnerable DLL is being restricted in any way
foreach kb_key (keys(qb_installs))
{
  product_name = kb_key - 'SMB/QuickBooks/' - '/path';
  path = qb_installs[kb_key];
  ver = _get_qb_version(product_name);

  # no need to go further if unable to get the version (which means this probably isn't QB 2008 - 2012)
  # or if the registry workaround is being used
  if (isnull(ver) || (report_paranoia < 2 && !reg_workaround_missing[ver])) continue;

  path += 'HelpAsyncPluggableProtocol.dll';
  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('unable to parse path: ' + path);
    continue;
  }

  share = match[1] + '$';
  dll = match[2];

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    err_print("Can't connect to "+share+" share.");
    continue;
  }

  fh = CreateFile(
    file:dll,
    desired_access:STANDARD_RIGHTS_READ | FILE_READ_DATA,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    sig = _get_pkcs7_sig(fh);
    dacl = _get_dacl(fh);
    CloseFile(handle:fh);
    patched = FALSE;
    workaround = FALSE;

    # first check if it's patched
    if (!isnull(sig))
    {
      signing_time = _get_signing_time(sig);

      # according to the Intuit Security Team, you can tell if the file has been patched
      # by checking if the signing date of the file is April 27, 2012 or later
      if (!isnull(signing_time) && _compare_times(signing_time, fixed_signing_time) >= 0)
        patched = TRUE;
    }

    # if not, check if a workaround is being used (unless paranoid)
    if (!patched && !isnull(dacl) && report_paranoia < 2)
      workaround = _check_file_workaround(dacl);

    if (!patched && !workaround)
    {
      vuln_installs[path] = signing_time;
    }
  }

  NetUseDel(close:FALSE);
}

NetUseDel();

if (max_index(keys(vuln_installs)) == 0)
  audit(AUDIT_INST_VER_NOT_VULN, appname);

if (report_verbosity > 0)
{
  report += '\nNessus determined the following files are unpatched :\n';

  foreach path (sort(keys(vuln_installs)))
  {
    report +=
      '\n  Path : ' + path;

    signing_date = vuln_installs[path];

    if (isnull(signing_date))
      report += '\n  Digital signature signing date : Not found';
    else
      report += '\n  Digital signature signing date : ' + _convert_utctime(signing_date);

    report += '\n  Expected signing date : ' + _convert_utctime(fixed_signing_time) + ' or later\n';
  }

  if (report_paranoia < 2)
  {
    report += '\nNo workarounds were detected for these files.\n';
  }
  else
  {
    report +=
      '\nNessus did not check if workarounds are being used because of the' +
      '\nReport Paranoia setting in effect when this scan was run.\n';
  }
     
  security_hole(port:port, extra:report);
}
else security_hole(port);
