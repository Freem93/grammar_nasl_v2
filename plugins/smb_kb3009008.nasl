#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78447);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/08/30 21:09:49 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"MS KB3009008: Vulnerability in SSL 3.0 Could Allow Information Disclosure (POODLE)");
  script_summary(english:"Checks if the workarounds referenced in the advisory have been applied.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in the
Microsoft Security Advisory 3009008.

If the client registry key workaround has not been applied, any client
software installed on the remote host (including IE) is affected by an
information disclosure vulnerability when using SSL 3.0.

If the server registry key workaround has not been applied, any server
software installed on the remote host (including IIS) is affected by
an information disclosure vulnerability when using SSL 3.0.

SSL 3.0 uses nondeterministic CBC padding, which allows a
man-in-the-middle attacker to decrypt portions of encrypted traffic
using a 'padding oracle' attack. This is also known as the 'POODLE'
issue.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/3009008");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/245030");
  # http://googleonlinesecurity.blogspot.de/2014/10/this-poodle-bites-exploiting-ssl-30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c60701b");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the client registry key workaround and the server registry key
workaround suggested by Microsoft in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

include('audit.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

ie_version = get_kb_item_or_exit("SMB/IE/Version");

registry_init();

# check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

foreach key (subkeys)
{
  if ('.DEFAULT' >< key || 'Classes' >< key ||
     key =~ "^S-1-5-\d{2}$") # skip built-in accounts
    continue;

  mitigation = FALSE;

  key_protocols = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\SecureProtocols';
  value = get_registry_value(handle:hku, item:key + key_protocols);

  if (isnull(value))
  {
    # By default this key won't exist and SSLv3 will be enabled
    # Once a user toggles any of the protocols, this key is created and contains the correct bitmask
    mitigation = FALSE;
  }

#    The SSLv3 flag is 32 (0x020).
  else if ((value & 0x020) == 0)
    mitigation = TRUE;

  if (!mitigation)
    info_user_settings += '\n    ' + key + ' (SSLv3 Enabled)';
}

RegCloseKey(handle:hku);

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

value = get_registry_value(handle:hklm, item:'Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\SecureProtocols');

if (!isnull(value) && ((value & 0x020) == 0))
  info_user_settings = ''; # mitigated by group policy which overrides user settings

# if this doesn't exist, it is enabled
# if this does exit and isn't 0, it is enabled
value = get_registry_value(handle:hklm, item:'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\\Enabled');
if (isnull(value) || int(value) != 0)
  server_ssl3_enabled = TRUE;
else
  server_ssl3_enabled = FALSE;

# if this doesn't exist, it is enabled
# if this does exit and isn't 0, it is enabled
value = get_registry_value(handle:hklm, item:'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client\\Enabled');
if (isnull(value) || int(value) != 0)
  client_ssl3_enabled = TRUE;
else
  client_ssl3_enabled = FALSE;

if (!client_ssl3_enabled && !server_ssl3_enabled)
  set_kb_item(name:"SMB/ssl_v3_poodle_workaround_enabled", value:TRUE);
else
  set_kb_item(name:"SMB/ssl_v3_poodle_workaround_enabled", value:FALSE);

RegCloseKey(handle:hklm);

close_registry();

if (client_ssl3_enabled || server_ssl3_enabled)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = '';
    if (server_ssl3_enabled)
    {
      report +=
        '\n' + 'The workaround to disable SSL 3.0 for all server software installed on' +
        '\n' + 'the remote host has not been applied.' +
        '\n';
    }

    if (client_ssl3_enabled)
    {
      report +=
        '\n' + 'The workaround to disable SSL 3.0 for all client software installed on' +
        '\n' + 'the remote host has not been applied.' +
        '\n';

      if (info_user_settings != '')
      {
        report +=
          '\n' + 'The following users on the remote host have vulnerable IE settings :' +
          '\n' + info_user_settings +
          '\n';
      }
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The host is not affected since a workaround has been applied.");
