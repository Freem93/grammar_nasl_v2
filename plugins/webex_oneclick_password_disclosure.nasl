#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69275);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/09 01:01:14 $");

  script_bugtraq_id(61304);
  script_osvdb_id(95379);

  script_name(english:"Cisco WebEx One-Click Password Disclosure");
  script_summary(english:"Decrypts the WebEx passwords from the registry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that stores credentials in an
insecure fashion.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Cisco WebEx One-Click installed that
stores credentials in the registry using a key that can be easily
derived.");
  # http://blog.opensecurityresearch.com/2013/07/quick-reversing-webex-one-click.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4105fde6");
  script_set_attribute(attribute:"see_also", value:"https://github.com/OpenSecurityResearch/onedecrypt/");
  script_set_attribute(attribute:"solution", value:"Configure the software to not remember passwords.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:webex:oneclick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("webex_oneclick_installed.nasl");
  script_require_keys("SMB/WebEx_OneClick/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

function decrypt(blob, plen, site, user)
{
  local_var i, iv, key, klen, res;

  # The key material is composed of (user || site) repeated until a
  # minimum length is reached.
  key = "";
  klen = 32;
  while (strlen(key) < klen)
    key += user + site;
  key = substr(key, 0, klen - 1);

  # Feed the IV as data through the AES encryption, yes, encryption.
  # We don't have ECB mode available, so we have to use CBC with a
  # blank IV.
  iv = raw_string(
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12
  );

  res = aes_cbc_encrypt(data:iv, key:key, iv:crap(data:raw_string(0), length:16));
  if (isnull(res))
    audit(AUDIT_FN_FAIL, "aes_cbc_encrypt", "NULL");
  res = substr(res[0], 0, plen - 1);

  # Xor the stored value from the registry with the encrypted IV to
  # recover the password.
  for (i = 0; i < plen; i++)
    res[i] = raw_string(ord(res[i]) ^ ord(blob[i]));

  return res;
}

get_kb_item_or_exit("SMB/WebEx_OneClick/Installed");

app = "WebEx One-Click";

# Pull install info from the KB.
kb_base = "SMB/WebEx_OneClick/";
version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

registry_init();
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);

creds = make_list();
key_h = RegOpenKey(handle:hku, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  reginfo = RegQueryInfoKey(handle:key_h);
  if (!isnull(reginfo))
  {
    for (i = 0; i < reginfo[1]; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (subkey !~ "^S-1-5-21-[-0-9]+$")
        continue;

      cred = make_list("SiteName", "UserName", "Password", "PasswordLen");
      for (j = 0; j < 4; j++)
      {
        key = subkey + "\Software\WebEx\ProdTools\" + cred[j];
        res = get_registry_value(handle:hku, item:key);
        if (isnull(res))
          break;

        cred[j] = res;
      }

      if (isnull(res))
        continue;

      cred[2] = decrypt(site:cred[0], user:cred[1], blob:cred[2], plen:cred[3]);
      creds[max_index(creds)] = cred;
    }
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hku);
close_registry();

if (max_index(creds) == 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, path);

if (report_verbosity > 0)
{
  foreach cred (creds)
  {
    # Asterisk out the center of the password.
    mangled = ereg_replace(string:cred[2], pattern:"(?<!^).(?!$)", replace:"*");

    report +=
      '\n  Site     : ' + cred[0] +
      '\n  Username : ' + cred[1] +
      '\n  Password : ' + mangled +
      '\n';
  }
}

security_warning(port:kb_smb_transport(),  extra:report);
