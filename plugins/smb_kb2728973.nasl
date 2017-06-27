# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59916);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/10 15:03:52 $");

  script_name(english:"MS KB2728973: Unauthorized Digital Certificates Could Allow Spoofing");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2728973, which updates the system's SSL
certificate blacklist."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2728973");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2728973");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2728973.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("byte_func.inc");
include("misc_func.inc");
include("kerberos_func.inc");

CERT_SHA1_HASH_PROP_ID = 0x3;
CERT_MD5_HASH_PROP_ID = 0x4;
CERT_KEY_IDENTIFIER_PROP_ID = 0x14;
CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x18;
CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x19;
CERT_CERT_PROP_ID = 0x20;
CERT_FIRST_USER_PROP_ID = 0x8000;

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

function der_parse_set (set,num,list)
{
 local_var tmp, dset, val, i, pos, ret;
 
 dset = der_decode (data:set);
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
  ret = der_decode (data:dset[1],pos:pos);
  if (isnull(ret))
    return NULL;
  
  val = ret[0] - 0xA0;
  if (val < 0)
    return NULL;
  
  tmp[val] = ret [1];
  pos = ret[2];
 }
 
 return tmp;
}

# compare 2 64-bit windows filetimes
# if(given_time < fixed_time) 
#   return -1
# if(given_time > fixed_time) 
#   return 1
# if(given_time == fixed_time) 
#   return 0
function compare_filetimes(given_time, fixed_time)
{
  local_var i;
  for(i=0; i<8; i++)
  {
     if(given_time[i] < fixed_time[i])
       return -1;
     if(given_time[i] > fixed_time[i])
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

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) audit(AUDIT_OS_SP_NOT_VULN); 
if ('Windows Embedded' >< productname)
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Thin OS');

# key = thumbprint, value = subject
certs = make_array(
'3A26012171855D4020C973BEC3F4F9DA45BD2B83','CN=Microsoft Online Svcs BPOS APAC CA4',
'43D9BCB568E039D073A74A71D8511F7476089CC3','DigiNotar Root CA G2',
'51C3247D60F356C7CA3BAF4C3F429DAC93EE7B74','Digisign Server ID (Enrich)',
'8E5BD50D6AE686D65252F843A9D4B96D197730AB','Digisign Server ID - (Enrich)',
'5DE83EE82AC5090AEA9D6AC4E7A6E213F946E179','DigiNotar PKIoverheid CA',
'2A83E9020591A55FC6DDAD3FB102794C52B24E70','Microsoft Enforced Licensing Intermediate PCA',
'3A850044D8A195CD401A680C012CB0A3B5F8DC08','Microsoft Enforced Licensing Intermediate PCA',
'FA6660A94AB45F6A88C0D7874D89A863D74DEE97','Microsoft Enforced Licensing Registration Authority CA (SHA1)',
'E38A2B7663B86796436D8DF5898D9FAA6835B238','Microsoft Genuine Windows Phone Public Preview CA01',
'BED412B1334D7DFCEBA3015E5F9F905D571C45CF','Microsoft IPTVe CA',
'A1505D9843C826DD67ED4EA5209804BDBB0DF502','Microsoft Online CA001',
'D43153C8C25F0041287987250F1E3CABAC8C2177','Microsoft Online Svcs BPOS APAC CA1',
'D8CE8D07F9F19D2569C2FB854401BC99C1EB7C3B','Microsoft Online Svcs BPOS APAC CA2',
'E95DD86F32C771F0341743EBD75EC33C74A3DED9','Microsoft Online Svcs BPOS APAC CA3',
'D0BB3E3DFBFB86C0EEE2A047E328609E6E1F185E','Microsoft Online Svcs BPOS APAC CA5',
'08738A96A4853A52ACEF23F782E8E1FEA7BCED02','Microsoft Online Svcs BPOS APAC CA6',
'7613BF0BA261006CAC3ED2DDBEF343425357F18B','Microsoft Online Svcs BPOS CA1',
'4ED8AA06D1BC72CA64C47B1DFE05ACC8D51FC76F','Microsoft Online Svcs BPOS CA2',
'587B59FB52D8A683CBE1CA00E6393D7BB923BC92','Microsoft Online Svcs BPOS CA2',
'F5A874F3987EB0A9961A564B669A9050F770308A','Microsoft Online Svcs BPOS CA2',
'A35A8C727E88BCCA40A3F9679CE8CA00C26789FD','Microsoft Online Svcs BPOS EMEA CA1',
'E9809E023B4512AA4D4D53F40569C313C1D0294D','Microsoft Online Svcs BPOS EMEA CA2',
'A7B5531DDC87129E2C3BB14767953D6745FB14A6','Microsoft Online Svcs BPOS EMEA CA3',
'330D8D3FD325A0E5FDDDA27013A2E75E7130165F','Microsoft Online Svcs BPOS EMEA CA4',
'09271DD621EBD3910C2EA1D059F99B8181405A17','Microsoft Online Svcs BPOS EMEA CA5',
'838FFD509DE868F481C29819992E38A4F7082873','Microsoft Online Svcs BPOS EMEA CA6',
'A221D360309B5C3C4097C44CC779ACC5A9845B66','Microsoft Online Svcs CA1',
'23EF3384E21F70F034C467D4CBA6EB61429F174E','Microsoft Online Svcs CA1',
'8977E8569D2A633AF01D0394851681CE122683A6','Microsoft Online Svcs CA3',
'374D5B925B0BD83494E656EB8087127275DB83CE','Microsoft Online Svcs CA3',
'6690C02B922CBD3FF0D0A5994DBD336592887E3F','Microsoft Online Svcs CA4',
'5D5185DF1EB7DC76015422EC8138A5724BEE2886','Microsoft Online Svcs CA4',
'A81706D31E6F5C791CD9D3B1B9C63464954BA4F5','Microsoft Online Svcs CA5',
'4DF13947493CFF69CDE554881C5F114E97C3D03B','Microsoft Online Svcs CA5',
'09FF2CC86CEEFA8A8BB3F2E3E84D6DA3FABBF63E','Microsoft Online Svcs CA6'
);

# the installer for Server 2008/Vista/7 adds additional revoked certificates
if (
  "Windows Vista" >< productname || 
  "Windows 7" >< productname ||
  "2008" >< productname)
{
  certs['305F8BD17AA2CBC483A4C41B19A39A0C75DA39D6'] = 'addons.mozilla.org';
  certs['61793FCBFA4F9008309BBA5FF12D2CB29CD4151A'] = 'global trustee';
  certs['9845A431D51959CAF225322B4A4FE9F223CE6D15'] = 'DigiNotar Cyber CA';
  certs['2B84BFBB34EE2EF949FE1CBE30AA026416EB2216'] = 'DigiNotar Cyber CA';
  certs['B86E791620F759F17B8D25E38CA8BE32E7D5EAC2'] = 'DigiNotar Cyber CA';
  certs['B533345D06F64516403C00DA03187D3BFEF59156'] = 'DigiNotar PKIoverheid CA';
  certs['40AA38731BD189F9CDB5B9DC35E2136F38777AF4'] = 'DigiNotar PKIoverheid CA';
  certs['86E817C81A5CA672FE000F36F878C19518D6F844'] = 'DigiNotar Root CA';
  certs['367D4B3B4FCBBC0B767B2EC0CDB2A36EAB71A4EB'] = 'DigiNotar Root CA';
  certs['C060ED44CBD881BD0EF86C0BA287DDCF8167478C'] = 'DigiNotar Root CA';
  certs['F8A54E03AADC5692B850496A4C4630FFEAA29D83'] = 'DigiNotar Services 1024 CA';
  certs['471C949A8143DB5AD5CDF1C972864A2504FA23C9'] = 'login.skype.com';
  certs['CEA586B2CE593EC7D939898337C57814708AB2BE'] = 'login.live.com';
  certs['63FEAE960BAA91E343CE2BD8B71798C76BDB77D0'] = 'login.yahoo.com';
  certs['80962AE4D6C5B442894E95A13E4A699E07D694CF'] = 'login.yahoo.com';
  certs['D018B62DC518907247DF50925BB09ACF4A5CB3AD'] = 'login.yahoo.com';
  certs['6431723036FD26DEA502792FA595922493030F97'] = 'mail.google.com';
  certs['1916A2AF346D399F50313C393200F14140456616'] = 'www.google.com';
}

cert_missing = FALSE;
thumbprint_mismatch = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\DisallowedCertEncodedCtl";
data = get_registry_value(handle:hklm, item:key);

if(!isnull(data) && data != '')
{
  res = get_effective_date_from_stl(stl_data:data);
  if(res['error'])
  {
    RegCloseKey(handle:hklm);
    close_registry();
    exit(1, res['value']);
  }
  if(strlen(res['value']) != 8)
  {
    RegCloseKey(handle:hklm);
    close_registry();
    exit(1, 'Expecting 64-bit Effective Date timestamp from Disallowed CTL.');
  }

  # 2012-06-21 23:06:31.9769699
  # Effective Date for KB2677070
  fixed_time = raw_string(0x01, 0xcd, 0x50, 0x02, 0x7f, 0x50, 0xc8, 0x63);
  if(compare_filetimes(given_time:res['value'], fixed_time:fixed_time) >= 0)
  {
    RegCloseKey(handle:hklm);
    close_registry();
    exit(0, 'Certificates have been disallowed by Auto-Updater. (KB2677070)');
  }
}

foreach thumbprint (keys(certs))
{
  blob = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint + "\Blob");

  # If the plugin fails to get the blob from a registry due to an error other than file not found,
  # something went wrong in the scan (e.g., request timed out) and we need to bail out.
  if (isnull(blob))
  {
    cert_missing = TRUE;
    err = session_get_errorcode();

    if (err != ERROR_FILE_NOT_FOUND)
    {
      RegCloseKey(handle:hklm);
      NetUseDel();
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

if (!cert_missing && !thumbprint_mismatch) audit(AUDIT_HOST_NOT, 'affected');

port = kb_smb_transport();

if (report_verbosity > 0)
{
  if (cert_missing)
  {
    report =
      '\nNessus was unable to open the following registry entry :\n\n' +
      "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint + "\Blob" +
      '\n\nThis indicates the update has not been applied.\n';
  }
  if (thumbprint_mismatch)
  {
    report =
      '\nThe thumbprint of the blacklisted certificate detected on the system does\n' +
      'not match the thumbprint of the certificate blacklisted by Microsoft :\n\n' +
      '  Subject  : ' + certs[thumbprint] + '\n' +
      '  Detected : ' + calculated_thumbprint + '\n' +
      '  Expected : ' + expected_thumbprint + '\n';
  }

  security_warning(port:port, extra:report);
}
else security_warning(port);
