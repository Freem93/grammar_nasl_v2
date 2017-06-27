#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62627);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/14 14:25:18 $");

  script_osvdb_id(85115);

  script_name(english:"Authentec UPEK Protector Suite Weak Password Storage");
  script_summary(english:"Tries to decrypt UPEK Protector user registry keys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an authentication product installed that does not
store user credentials in a secure manner."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has, or has had Authentec UPEK Protector Suite
installed.  Nessus was able to decrypt user credentials stored in an
insecure manner in the Windows registry by UPEK Protector Suite."
  );
  script_set_attribute(attribute:"see_also", value:"http://adamcaudill.com/2012/10/07/upek-windows-password-decryption/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/brandonlw/upek-ps-pass-decrypt");
  # http://support.authentec.com/Downloads/Windows/ProtectorSuite/PS2012.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a31f585e");
  # http://blog.crackpassword.com/2012/08/upek-fingerprint-readers-a-huge-security-hole/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63613739");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the vendor's patch or uninstall UPEK Protector Suite along with
the stored user credentials."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:authentec:protector_suite");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

#########################################################################
#  Args:                                                                #
#      key_data  : ExData registry value                                #
#  Returns:                                                             #
#      ret_arr['is_error']         : TRUE/FALSE                         #
#      ret_arr['can_decrypt']      : TRUE/FALSE                         #
#      ret_arr['err_msg']          : Error message string               #
#      ret_arr['decrypted_creds']  : String containing decrypted creds  #
#########################################################################

function decryptExData(key_data)
{
  local_var md5_seed, md5_iterations, type, bit_len, data_offset, data_len,
            data, iv_len, iv, key_pad_len, encryption_key, decrypted_data, 
            ret, i, out_next, out_domain, out_creds, decoded_str,
            field_size, decrypted_creds, ret_arr, key_data_len, hide_pass;

  key_data_len = strlen(key_data);

  ret_arr = make_array();
  ret_arr['can_decrypt'] = FALSE;
  ret_arr['is_error'] = FALSE;

  if (key_data_len < 21)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'ExData registry value is not long enough.';
    return ret_arr;
  }
  md5_seed = raw_string(0xEA, 0x59, 0x40, 0xC3, 0xB9, 0x41, 0x9C, 0xD2, 
                        0xEB, 0x72, 0x96, 0xEF, 0x70, 0xD9, 0xAA, 0x2F);
  md5_iterations = 1001;
  for (i=0; i<md5_iterations; i++)
    md5_seed = MD5(md5_seed);

  type = get_dword(blob:key_data, pos: 4);

  # Starting at 0x05, data is further protected by patch with DPAPI
  if (type >= 5) return ret_arr;

  bit_len = get_dword(blob:key_data, pos:16);

  if (bit_len > 256 || bit_len < 56)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Invalid key bit length.';
    return ret_arr;
  }
  data_offset = 20;

  data_len = get_dword(blob:key_data, pos:data_offset);
  if (data_len <= 0)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'ExData is missing encrypted data.';
    return ret_arr;
  }
  
  # AES has a 128 bit block size
  if (data_len < 16 || data_len % 16 != 0)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Invalid data length.';
    return ret_arr;
  }

  # ensure that we can read data and iv_len 
  if (key_data_len < (data_offset + data_len + 4 + 4))
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'ExData registry value is not long enough.';
    return ret_arr;
  }

  data = substr(key_data, data_offset + 4, data_offset + 4 + (data_len - 1));

  iv_len = get_dword(blob:key_data, pos:data_offset + 4 + data_len);
  if (iv_len > 16 || iv_len < 0)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Invalid IV length.';
    return ret_arr;
  }
 
  # ensure that we can read iv 
  if (key_data_len < (data_offset + data_len + 4 + 4 + iv_len))
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'ExData registry value is not long enough.';
    return ret_arr;
  }

  iv = substr(key_data, data_offset + 4 + data_len + 4, 
                        data_offset + 4 + data_len + 4 + (iv_len - 1));

  key_pad_len = 0;
  if (iv_len == 7) key_pad_len = 32;
  else key_pad_len = iv_len / 8;
  
  if (key_pad_len != 32 && key_pad_len != 24 && key_pad_len != 16)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Invalid key size.';
    return ret_arr;
  } 
 
  encryption_key = '';
    
  # Derive Encryption Key 
  for (i=0; i<(bit_len+7)/8; i++)
  {
    md5_seed = MD5(md5_seed);
    encryption_key += md5_seed[11]; 
  }

  if (strlen(encryption_key) > 32 || strlen(encryption_key) > key_pad_len)
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Invalid bit length value specified.';
    return ret_arr;
  }

  # Pad IV/Encryption Key
  for (i=strlen(encryption_key); i<key_pad_len; i++)
     encryption_key += raw_string(0x00);

  for (i=iv_len; i<16; i++)
     iv += raw_string(0x00);
    
  ret = aes_cbc_decrypt(data:data, key:encryption_key, iv:iv);
   
  decrypted_data = ret[0];

  if (
    decrypted_data[8] == 'P' && decrypted_data[9] == 'S' &&
    decrypted_data[10] == '1'
  )
  {
    out_next = FALSE;
    out_domain = FALSE;
    hide_pass = FALSE;

    decrypted_creds = '';

    ret_arr['can_decrypt'] = TRUE;

    for (i=0; i<strlen(decrypted_data)-3; i++)
    {
      if (
        decrypted_data[i]     == raw_string(0xB0) && 
        decrypted_data[i + 1] == raw_string(0x04) &&
        decrypted_data[i + 2] == raw_string(0x00) && 
        decrypted_data[i + 3] == raw_string(0x00)
      )
      {
        field_size = get_dword(blob:decrypted_data, pos:i-4);
        decoded_str = unicode2ascii(string:substr(decrypted_data, i+4, i + field_size));
 
        if (out_next)
        {
          if (out_domain && decoded_str != 'P1' && decoded_str != '0x11')
          {
            decrypted_creds += '  Domain : ';
            decrypted_creds += decoded_str + '\n';
          }
          else if (!out_domain) 
          {
            if(hide_pass)
              decrypted_creds = decoded_str[0] + crap(data:"*", length:6) + decoded_str[strlen(decoded_str)-1] + '\n';
            else decrypted_creds += decoded_str + '\n';
          }
        }  

        out_next = FALSE;
        out_domain = FALSE;
        hide_pass = FALSE;

        if (decoded_str == 'P1')
        {
          decrypted_creds += '  Password : ';
          out_next = TRUE;
          hide_pass = TRUE;
        }
        if (decoded_str == '0x12')
        {
          out_next = TRUE;
          out_domain = TRUE;
        }
        if (decoded_str == '0x11')
        {
          decrypted_creds += '  User Name : ';
          out_next = TRUE;
        }
      }  
    }
    if (decrypted_creds != '')
      ret_arr['decrypted_creds'] = decrypted_creds;
    else
      ret_arr['decrypted_creds'] = NULL;
  }
  else
  {
    ret_arr['is_error'] = TRUE;
    ret_arr['err_msg'] = 'Unable to decrypt ExData.';
  }
  return ret_arr;
}

vulnerable_registry_keys = make_list(
  "Software\Virtual Token\Passport\2.0\Passport",
  "Software\Virtual Token\Passport\2.0\LocalPassport",
  "Software\Virtual Token\Passport\2.0\DevicePassport",
  "Software\Virtual Token\Passport\2.0\VoidPassport",
  "Software\Virtual Token\Passport\3.0\Passport",
  "Software\Virtual Token\Passport\3.0\LocalPassport",
  "Software\Virtual Token\Passport\3.0\DevicePassport",
  "Software\Virtual Token\Passport\3.0\VoidPassport",
  "Software\Virtual Token\Passport\4.0\Passport",
  "Software\Virtual Token\Passport\4.0\LocalPassport",
  "Software\Virtual Token\Passport\4.0\DevicePassport",
  "Software\Virtual Token\Passport\4.0\VoidPassport"
);

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

user_creds = '';
decrypted_keys = make_list();
error_messages = make_list();

vuln = FALSE;
patched = FALSE;

foreach key (vulnerable_registry_keys)
{
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  if (isnull(subkeys)) continue;

  foreach subkey (subkeys)
  {
    exdata = get_registry_value(handle:hklm, item:key + '\\' + subkey + '\\ExData');
    if (!isnull(exdata))
    {
      ret = decryptExData(key_data:exdata);
      if (ret['can_decrypt'])
      {
        vuln = TRUE;
        decrypted_keys = make_list(decrypted_keys, 
                                   '  HKLM\\' + key + '\\' + subkey + '\\ExData');
      }
      if (!isnull(ret['decrypted_creds']))
        user_creds += ret['decrypted_creds'];
      if (ret['is_error'])
        error_messages = make_list(error_messages, ret['err_msg']);
      if (!ret['is_error'] && !ret['can_decrypt'])
        patched = TRUE;
    }
  }
}

RegCloseKey(handle:hklm);

close_registry();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to decrypt the following registry key';
    if (max_index(decrypted_keys) == 1)
      report += ' :\n';
    else report += 's :\n';
    report += join(decrypted_keys, sep:'\n') + '\n';
 
    if (user_creds != '')
      report += '\nNessus was able to extract the following user credentials : \n' +
                user_creds;
  
    if (max_index(error_messages) > 0)
    {
      report += '\nThese results may be incomplete due to the following error';
      if (max_index(error_messages) == 1)
        report += ' :\n';
      else report += 's :\n';
      report += join(error_messages, sep:'\n');
      report += '\n';
    }
    security_note(extra:report, port:port); 
  } 
   else security_note(port);
}
else 
{
  if (max_index(error_messages) > 0)
  {
    err_report += '\nError';
    if (max_index(error_messages) == 1)
      err_report += ' :\n';
    else err_report += 's :\n';
    err_report += join(error_messages, sep:'\n');
    err_report += '\n';
    exit(1, err_report);
  }
  else
  {
    if (patched)
      exit(0, 'Nessus was unable to decrypt any UPEK Protector registry keys. UPEK patch has been applied.');
    else
      exit(0, 'No vulnerable registry keys found.');
  }
}
