#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87313);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_osvdb_id(130575);
  script_xref(name:"CERT", value:"870761");
  script_xref(name:"IAVA", value:"2015-A-0307");
  script_xref(name:"CERT", value:"925497");

  script_name(english:"MS KB3119884: Improperly Issued Digital Certificates Could Allow Spoofing");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an out-of-date SSL certificate blacklist.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB3119884, KB2677070 (automatic updater),
or the latest disallowed certificate update using KB2813430 (manual
updater). If KB2677070 has been installed, it has not yet obtained the
latest auto-updates.

Note that this plugin checks that the updaters have actually updated
the disallowed CTL list, not that the KBs listed are installed. This
approach was taken since the KB2677070 automatic updater isn't
triggered unless software that relies on SSL in the Microsoft
Cryptography API is being actively used on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3119884");
  # https://support.microsoft.com/en-us/help/3050995/microsoft-security-advisory-improperly-issued-digital-certificates-could-allow-spoofing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?472117a2");
  # https://support.microsoft.com/en-us/help/2677070/an-automatic-updater-of-untrusted-certificates-is-available-for-windows-vista,-windows-server-2008,-windows-7,-and-windows-server-2008-r2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae862e27");
  # https://support.microsoft.com/en-us/help/2813430/an-update-is-available-that-enables-administrators-to-update-trusted-and-disallowed-ctls-in-disconnected-environments-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a944e0bb");
  script_set_attribute(attribute:"solution", value:
"Ensure that the Microsoft automatic updater for revoked certificates
(KB2677070) is installed and running. Alternatively, install the
manual updater (KB2813430).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/11/30");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_qfes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("byte_func.inc");
include("misc_func.inc");

CERT_SHA1_HASH_PROP_ID = 0x3;
CERT_MD5_HASH_PROP_ID = 0x4;
CERT_KEY_IDENTIFIER_PROP_ID = 0x14;
CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x18;
CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x19;
CERT_CERT_PROP_ID = 0x20;
CERT_FIRST_USER_PROP_ID = 0x8000;

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

function der_parse_set(set,num,list)
{
 local_var tmp, dset, val, i, pos, ret;

 dset = der_decode(data:set);
 if (isnull(dset) || (dset[0] != 0x31))
   return NULL;

 if (!isnull(list) && (list == TRUE))
   return der_parse_list (list:dset[1]);

 tmp = NULL;
 for (i=0; i < num; i++)
   tmp[i] = NULL;

 pos = i = 0;
 while (pos < strlen(dset[1]))
 {
  ret = der_decode(data:dset[1],pos:pos);
  if (isnull(ret))
    return NULL;

  val = ret[0] - 0xA0;
  if (val < 0)
    return NULL;

  tmp[val] = ret[1];
  pos = ret[2];
 }

 return tmp;
}

# compare 2 64-bit windows filetimes
# if (given_time < fixed_time)
#   return -1
# if (given_time > fixed_time)
#   return 1
# if (given_time == fixed_time)
#   return 0
function compare_filetimes(given_time, fixed_time)
{
  local_var i;
  for(i=0; i<8; i++)
  {
     if (given_time[i] < fixed_time[i])
       return -1;
     if (given_time[i] > fixed_time[i])
       return 1;
  }
  return 0;
}

# Returns Effective Date From STL / CTL
function get_effective_date_from_stl(stl_data)
{
  local_var retval;
  retval = make_array();
  retval['error'] = TRUE;

  local_var OID_PKCS_7_2, OID_CTL, TAG_OBJ, TAG_INT, top,
            obj, oid, pkcs, eci, ver, algs, set, i, seq,
            filetime;
  OID_PKCS_7_2 = "1.2.840.113549.1.7.2";
  OID_CTL = "1.3.6.1.4.1.311.10.1";

  TAG_OBJ = 0xA0;
  TAG_INT = 0x02;

  top = der_parse_sequence(seq:stl_data, list:TRUE);
  if (isnull(top))
  {
    retval['value'] = "Failed to parse CTL.";
    return retval;
  }
  if (top[0] < 2)
  {
    retval['value'] = "Too few elements at top level of CTL.";
    return retval;
  }
  oid = der_parse_oid(oid:top[1]);
  if (oid != OID_PKCS_7_2)
  {
    retval['value'] = "OID '" + oid + "' not recognized.";
    return retval;
  }

  obj = der_parse_data(tag:TAG_OBJ, data:top[2]);
  if (isnull(obj))
  {
    retval['value'] = "Failed to parse container.";
    return retval;
  }

  pkcs = der_parse_sequence(seq:obj, list:TRUE);
  if (isnull(pkcs))
  {
    retval['value'] = "Failed to parse PKCS #7 container.";
    return retval;
  }

  if (pkcs[0] < 5)
  {
    retval['value'] = "Too few elements in the PKCS #7 container.";
    return retval;
  }

  # Cryptographic Message Syntax Version
  ver = der_parse_int(i:pkcs[1]);
  if (isnull(ver))
  {
    retval['value'] = "Failed to parse version.";
    return retval;
  }
  if (ver != 1)
  {
    retval['value'] = "No support for version " + ver + ".";
    return retval;
  }

  # Digest Algorithms
  set = der_parse_set(set:pkcs[2], list:TRUE);
  if (isnull(set))
  {
    retval['value'] = "Failed to parse digest algorithms.";
    return retval;
  }
  if (set[0] < 1)
  {
    retval['value'] = "No digest algorithms listed.";
    return retval;
  }

  algs = make_list();
  for (i = 0; i < set[0]; i++)
  {
    algs[i] = der_parse_oid(oid:top[1]);
    if (isnull(algs[i]))
    {
      retval['value'] = "Failed to parse digest algorithm " + i + ".";
      return retval;
    }
  }

  # Encapsulated Content Info
  eci = der_parse_sequence(seq:pkcs[3], list:TRUE);
  if (isnull(pkcs))
  {
    retval['value'] = "Failed to parse Encapsulated Content Info sequence.";
    return retval;
  }
  if (eci[0] < 2)
  {
    retval['value'] = "Too few elements in the Encapsulated Content Info sequence container.";
    return retval;
  }
  oid = der_parse_oid(oid:eci[1]);
  if (oid != OID_CTL)
  {
    retval['value'] = "Encapsulated Content Info OID '" + oid + "' not recognized.";
    return retval;
  }

  obj = der_parse_data(tag:TAG_OBJ, data:eci[2]);
  if (isnull(obj))
  {
    retval['value'] = "Failed to parse undocumented container.";
    return retval;
  }

  eci = der_parse_sequence(seq:obj, list:TRUE);
  if (isnull(eci))
  {
    retval['value'] = "Failed to parse inner Encapsulated Content Info sequence.";
    return retval;
  }
  if (eci[0] < 6)
  {
    retval['value'] = "Too few elements in the inner Encapsulated Content Info sequence container.";
    return retval;
  }

  seq = der_parse_sequence(seq:eci[1], list:TRUE);
  if (isnull(seq))
  {
    retval['value'] = "Failed to parse inner undocumented container.";
    return retval;
  }
  if (seq[0] < 1)
  {
    retval['value'] = "Too few elements in the undocumented container.";
    return retval;
  }

  # States purpose of certs, nothing in Google.
  oid = der_parse_oid(oid:seq[1]);
  if (oid != "1.3.6.1.4.1.311.10.3.30")
  {
    retval['value'] = "OID '" + oid + "' not recognized.";
    return retval;
  }

  filetime = der_parse_data(tag:TAG_INT, data:eci[3]);
  if (isnull(filetime))
  {
    retval['value'] = "Failed to parse effective date.";
    return retval;
  }
  retval['error'] = FALSE;
  retval['value'] = filetime;
  return retval;
}

##
# parses the records contained in a certificate registry blob
#
# @anonparam blob the blob to parse
# @return a hash of records, where the key is the property ID and the value is the data
##
function _parse_blob()
{
  local_var blob, ret, i, propid, rec_len, rec_data;
  blob = _FCT_ANON_ARGS[0];
  i = 0;
  ret = make_array();

  # try to parse the blob, one record at a time
  while (i < strlen(blob))
  {
    propid = get_dword(blob:blob, pos:i); i += 4;
    i += 4;  # this field is an unknown dword
    rec_len = get_dword(blob:blob, pos:i); i += 4;
    rec_data = substr(blob, i, i + rec_len - 1); i += rec_len;

    ret[propid] = rec_data;
  }

  return ret;
}

productname = get_kb_item_or_exit('SMB/ProductName');
os_ver = get_kb_item_or_exit('SMB/WindowsVersion');
qfes = get_kb_item("SMB/Microsoft/qfes");

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ('Windows Embedded' >< productname)
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Thin OS');

# key = thumbprint, value = subject
# There is not an update that adds this yet, but it is listed in the advisory FAQ
certs = make_array(
  '98A04E4163357790C4A79E6D713FF0AF51FE6927', 'eDellRoot',
  '02C2D931062D7B1DC2A5C7F5F0685064081FB221', 'DSDTestProvider'
);

cert_missing = FALSE;
thumbprint_mismatch = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\DisallowedCertEncodedCtl";
data = get_registry_value(handle:hklm, item:key);

fixed_time = '';

if (!isnull(data) && data != '')
{
  res = get_effective_date_from_stl(stl_data:data);
  if (res['error'])
  {
    RegCloseKey(handle:hklm);
    close_registry();
    exit(1, res['value']);
  }
  if (strlen(res['value']) != 8)
  {
    RegCloseKey(handle:hklm);
    close_registry();
    exit(1, 'Expecting 64-bit Effective Date timestamp from Disallowed CTL.');
  }

  # 01d1270874585de1 (2015-11-24 22:35:43.562492)
  # Effective Date for KB2677070

  fixed_time = raw_string(0x01, 0xd1, 0x27, 0x08, 0x74, 0x58, 0x5d, 0xe1);

  if (compare_filetimes(given_time:res['value'], fixed_time:fixed_time) >= 0)
  {
    RegCloseKey(handle:hklm);
    close_registry();
    replace_kb_item(name:"SMB/OOBKB/3119884", value:TRUE);
    exit(0, 'Certificates have been disallowed by Auto-Updater.');
  }
}

foreach thumbprint (keys(certs))
{
  blob = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint + "\Blob");
  if(isnull(blob))
    blob = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint + "\Blob");

  # If the plugin fails to get the blob from a registry due to an error other than file not found (and ERROR_SUCCESS for some edge cases),
  # something went wrong in the scan (e.g., request timed out) and we need to bail out.
  if (isnull(blob))
  {
    cert_missing = TRUE;
    err = session_get_errorcode();

    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_SUCCESS)
    {
      RegCloseKey(handle:hklm);
      close_registry();
      audit(AUDIT_FN_FAIL, 'get_registry_value', 'error code ' + error_code_to_string(err));
    }
  }
  else
  {
    blob = _parse_blob(blob);
    der_cert = blob[CERT_CERT_PROP_ID];
  }

  # this initial if will be true if
  # 1) the blob wasn't found in the registry, or
  # 2) the cert couldn't be parsed from the blob
  if (isnull(der_cert))
  {
    cert_missing = TRUE;
    break;
  }

  calculated_thumbprint = toupper(hexstr(SHA1(der_cert)));
  expected_thumbprint = toupper(thumbprint);

  if (calculated_thumbprint != expected_thumbprint)
  {
    thumbprint_mismatch = TRUE;
    break;
  }
}

RegCloseKey(handle:hklm);
close_registry();

if (!cert_missing && !thumbprint_mismatch)
{
  replace_kb_item(name:"SMB/OOBKB/3119884", value:TRUE);
  audit(AUDIT_HOST_NOT, 'affected');
}

port = kb_smb_transport();

if (report_verbosity > 0)
{
  if (fixed_time != '')
  {
    report =
      '\n' + 'Nessus has determined that the CTL is out of date and is missing an automatic' +
      '\n' + 'update.' +
      '\n'  +
      '\n' + '  Found timestamp    : ' + hexstr(res['value']) +
      '\n' + '  Expected timestamp : ' + hexstr(fixed_time) +
      '\n';
  }

  if('KB2677070' >< qfes || 'KB2813430' >< qfes)
  {
    report =
    '\n' + 'The remote host has KB2677070 or KB2813430, but the disallowed' +
    '\n' + 'CTL has not been updated.\n';
  }
  else
  {
    if(isnull(qfes))
    {
      report =
      '\n' + 'The remote host is missing a disallowed CTL update or the' +
      '\n' + 'Rvkroots.exe update package.\n';
    }
    else
    {
      report =
      '\n' + 'The remote host is missing KB2677070 / KB2813430 or the' +
      '\n' + 'Rvkroots.exe update package.\n';
    }
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);
