# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59357);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/10 15:03:52 $");

  script_bugtraq_id(53760);
  script_osvdb_id(82693);

  script_name(english:"MS KB2718704: Unauthorized Digital Certificates Could Allow Spoofing (deprecated)");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  ); 
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2718704, which updates the system's SSL
certificate blacklist.

Certificates issued by the Microsoft Terminal Services licensing
certification authority can be used to sign code as Microsoft.  An
attacker could exploit this to spoof content or perform
man-in-the-middle attacks. KB2718704 revokes the trust of the three
intermediate CA certificates that can be used to perform this attack."
  );
  script_set_attribute(attribute:"see_also",value:"http://technet.microsoft.com/en-us/security/advisory/2718704");
  # http://blogs.technet.com/b/srd/archive/2012/06/03/microsoft-certification-authority-signing-certificates-added-to-the-untrusted-certificate-store.aspx
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?239cac64");
  script_set_attribute(attribute:"see_also",value:"http://support.microsoft.com/kb/2718704");
  script_set_attribute(
    attribute:"solution",
    value:"Install Microsoft KB2718704."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/03");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("byte_func.inc");
include("misc_func.inc");
include("audit.inc");

CERT_SHA1_HASH_PROP_ID = 0x3;
CERT_MD5_HASH_PROP_ID = 0x4;
CERT_KEY_IDENTIFIER_PROP_ID = 0x14;
CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x18;
CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x19;
CERT_CERT_PROP_ID = 0x20;
CERT_FIRST_USER_PROP_ID = 0x8000;

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

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

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0)
  audit(AUDIT_HOST_NOT, 'affected based on its version / service pack'); 
if ('Windows Embedded' >< get_kb_item_or_exit('SMB/ProductName'))
  audit(AUDIT_INST_VER_NOT_VULN, 'Windows Thin OS');

# key = thumbprint, value = subject
certs = make_array(
  '2A83E9020591A55FC6DDAD3FB102794C52B24E70', 'Microsoft Enforced Licensing Intermediate PCA',
  '3A850044D8A195CD401A680C012CB0A3B5F8DC08', 'Microsoft Enforced Licensing Intermediate PCA',
  'FA6660A94AB45F6A88C0D7874D89A863D74DEE97', 'Microsoft Enforced Licensing Registration Authority CA (SHA1)'
);
cert_missing = FALSE;
thumbprint_mismatch = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

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

if (!cert_missing && !thumbprint_mismatch)
  audit(AUDIT_HOST_NOT, 'affected');

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

