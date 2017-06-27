# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52977);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/10 15:03:52 $");

  script_name(english:"MS KB2524375: Fraudulent Digital Certificates Could Allow Spoofing (deprecated)");
  script_summary(english:"Checks if the relevant certs are blacklisted in the registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB2524375, which updates the system's SSL
certificate blacklist.

A certificate authority (CA) has revoked a number of fraudulent SSL
certificates for several prominent, public websites. Without this
update, browsers will be unable to learn that the certificates have
been revoked if either Online Certificate Status Protocol (OCSP) is
disabled, or OCSP is enabled and fails.

If an attacker can trick someone into using the affected browser and
visiting a malicious site using one of the fraudulent certificates, he
may be able to fool that user into believing the site is a legitimate
one. In turn, the user could send credentials to the malicious site or
download and install applications.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8fdcaa8");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/2524375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.microsoft.com/kb/2524375"
  );
  script_set_attribute(attribute:"solution", value:"Apply the relevant update provided by Microsoft.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

include('audit.inc');
include('smb_header.inc');
include('smb_internals.inc');
include('smb2_func.inc');
include('smb_func.inc');
include('smb_cifs.inc');
include('smb_dcerpc.inc');
include('smb_net.inc');
include('smb_sam.inc');
include('smb_lsa.inc');
include('smb_file.inc');
include('smb_reg.inc');
include('smb_svc.inc');
include('x509_func.inc');
include('smb_hotfixes.inc');

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
# @anonparam  blob  the blob to parse
# @return a hash of records, where the key is the property ID and the value is the data
##
function parse_blob()
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

domains = make_array(
  '1916A2AF346D399F50313C393200F14140456616', 'www.google.com',
  '305F8BD17AA2CBC483A4C41B19A39A0C75DA39D6', 'addons.mozilla.org',
  '471C949A8143DB5AD5CDF1C972864A2504FA23C9', 'login.skype.com',
  '61793FCBFA4F9008309BBA5FF12D2CB29CD4151A', 'global trustee',
  '63FEAE960BAA91E343CE2BD8B71798C76BDB77D0', 'login.yahoo.com',
  '6431723036FD26DEA502792FA595922493030F97', 'mail.google.com',
  '80962AE4D6C5B442894E95A13E4A699E07D694CF', 'login.yahoo.com',
  'CEA586B2CE593EC7D939898337C57814708AB2BE', 'login.live.com',
  'D018B62DC518907247DF50925BB09ACF4A5CB3AD', 'login.yahoo.com'
);

serials = make_array(
  '1916A2AF346D399F50313C393200F14140456616', '00f5c86af36162f13a64f54f6dc9587c06',
  '305F8BD17AA2CBC483A4C41B19A39A0C75DA39D6', '009239d5348f40d1695a745470e1f23f43',
  '471C949A8143DB5AD5CDF1C972864A2504FA23C9', '00e9028b9578e415dc1a710a2b88154447',
  '61793FCBFA4F9008309BBA5FF12D2CB29CD4151A', '00d8f35f4eb7872b2dab0692e315382fb0',
  '63FEAE960BAA91E343CE2BD8B71798C76BDB77D0', '00d7558fdaf5f1105bb213282b707729a3',
  '6431723036FD26DEA502792FA595922493030F97', '047ecbe9fca55f7bd09eae36e10cae1e',
  '80962AE4D6C5B442894E95A13E4A699E07D694CF', '3e75ced46b693021218830ae86a82a71',
  'CEA586B2CE593EC7D939898337C57814708AB2BE', '00b0b7133ed096f9b56fae91c874bd3ac0',
  'D018B62DC518907247DF50925BB09ACF4A5CB3AD', '392a434f0e07df1f8aa305de34e0c229'
);

if ('Windows Embedded' >< get_kb_item_or_exit('SMB/ProductName'))
  exit(0, 'The host is running Windows Thin OS, and thus is not affected.');

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) audit(AUDIT_OS_SP_NOT_VULN);

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# tells if the most recently queried blacklisted cert is
# 1) missing from the registry, or
# 2) in the registry, but the cert doesn't match up with the cert blacklisted by MS
key_missing = FALSE;   # registry key where the cert is contained
cert_missing = FALSE;  # the actual blob/cert data itself
thumbprint_mismatch = FALSE;
serial_mismatch = FALSE;

foreach thumbprint (sort(keys(domains)))
{
  key = "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (isnull(key_h))
  {
    key_missing = TRUE;
    err = session_get_errorcode();

    # If the plugin fails to get the blob from a registry due to an error other than file not found,
    # something went wrong in the scan (e.g., request timed out) and we need to bail out.
    if (err != ERROR_FILE_NOT_FOUND)
    {
      RegCloseKey(handle:hklm);
      NetUseDel();
      audit(AUDIT_FN_FAIL, 'RegOpenKey', 'error code ' + error_code_to_string(err));
    }
  }

  # if it looks like the patch was installed, verify that the correct
  # cert is being blacklisted
  if (!key_missing)
  {
    blob = RegQueryValue(handle:key_h, item:"Blob");

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
        audit(AUDIT_FN_FAIL, 'RegOpenKey', 'error code ' + error_code_to_string(err));
      }
    }
    else
    {
      blob = parse_blob(blob[1]);
      der_cert = blob[CERT_CERT_PROP_ID];
    }

    if (!isnull(der_cert))
    {
      cert_thumbprint = toupper(hexstr(SHA1(der_cert)));
      expected_thumbprint = toupper(thumbprint);

      cert = parse_der_cert(cert:der_cert);
      tbs = cert["tbsCertificate"];
      cert_serial = hex_buf(buf:tbs["serialNumber"], space:0);
      cert_serial = toupper(str_replace(find:" ", replace:"", string:cert_serial));
      expected_serial = toupper(serials[thumbprint]);

      if (cert_thumbprint != expected_thumbprint)
        thumbprint_mismatch = TRUE;
      else if (cert_serial != expected_serial)
        serial_mismatch = TRUE;
    }

    RegCloseKey(handle:key_h);
  }

  # stop at the first sign that the update hasn't been applied / applied properly
  if (key_missing || cert_missing || thumbprint_mismatch || serial_mismatch) break;
}

RegCloseKey(handle:hklm);
NetUseDel();

if (!key_missing && !cert_missing && !thumbprint_mismatch && !serial_mismatch)
  exit(0, 'The host is not affected.');

if (report_verbosity > 0)
{
  if (key_missing)
  {
    report =
      '\nNessus was unable to open the following registry key :\n\n' +
      "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint +
      '\n\nThis indicates the update has not been applied.\n';
  }
  if (cert_missing)
  {
    report =
      '\nNessus was unable to open the following registry entry :\n\n' +
      "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\" + thumbprint + "\Blob" +
      '\n\nThis indicates the update may not have been applied properly.\n';
  }
  if (thumbprint_mismatch)
  {
    report =
      '\nThe thumbprint of the blacklisted certificate for domain "'+domains[thumbprint]+'"\n' +
      'does not match the thumbprint of the certificate blacklisted by Microsoft :\n\n' +
      '  Detected : ' + cert_thumbprint + '\n' +
      '  Expected : ' + thumbprint + '\n';
  }
  if (serial_mismatch)
  {
    report =
      '\nThe serial number of the blacklisted certificate for domain "'+domains[thumbprint]+'"\n' +
      'does not match the serial number of the certificate blacklisted by Microsoft :\n\n' +
      '  Detected : ' + cert_serial + '\n' +
      '  Expected : ' + expected_serial + '\n';
  }

  security_warning(port:port, extra:report);
}
else security_warning(port);
