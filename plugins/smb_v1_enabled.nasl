#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97086);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/09 22:07:05 $");

  script_osvdb_id(151058);

  script_name(english:"Server Message Block (SMB) Protocol Version 1 Enabled");
  script_summary(english:"Checks if SMBv1 is enabled in the registry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host supports the SMBv1 protocol.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host supports Server Message Block Protocol
version 1 (SMBv1). Microsoft recommends that users discontinue the use
of SMBv1 due to the lack of security features that were included in
later SMB versions. Additionally, the Shadow Brokers group reportedly
has an exploit that affects SMB; however, it is unknown if the exploit
affects SMBv1 or another version. In response to this, US-CERT
recommends that users disable SMBv1 per SMB best practices to mitigate
these potential issues.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/2696547");
  # https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dcab5e4");
  # http://www.theregister.co.uk/2017/01/18/uscert_warns_admins_to_kill_smb_after_shadow_brokers_dump/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36fd3072");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Disable SMBv1 according to the vendor instructions in Microsoft
KB2696547. Additionally, block SMB directly by blocking TCP port 445
on all network boundary devices. For SMB over the NetBIOS API, block
TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary
devices.");
  script_set_attribute(attribute:"risk_factor", value: "None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("dump.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
os_ver      = get_kb_item_or_exit('SMB/WindowsVersion');

smb_v1_server_enabled          = NULL;
smb_v1_windows_feature_enabled = NULL;
smb_v1_client_enabled          = NULL;

server_key                     = NULL;
smb_v1_windows_feature_key     = NULL;
client_key                     = NULL;
report                         = '';

# OSes that support SMBv2 or greater
if (hotfix_check_sp_range(vista:'0,2', win7:'0,1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# SMB Server
key = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1";
data = get_registry_value(handle:hklm, item:key);
if (empty_or_null(data) || data != 0)
{
  server_key = key;
  server_key_value = data;
  smb_v1_server_enabled = TRUE;
}

# If feature is _removed_ completely, the above key is absent.
# Extra check for SMB1 features FS-SMB1 or SMB1protocol
# in Windows 8.1, 10, Server 2012 R2, and 2016 by registry key.
# The services registry key is removed by the process.
if (
  smb_v1_server_enabled &&
  (hotfix_check_sp_range(win81:'0', win10:'0') > 0)
)
{
  key = "SYSTEM\CurrentControlSet\Services\srv";
  data = get_values_from_key(handle:hklm, key:key, entries:make_list('DisplayName', 'Start'));
  if (!empty_or_null(data))
  {
    smb_v1_windows_feature_key = key;
    smb_v1_windows_feature_enabled = TRUE;
  }
  else
  {
    # Target is : 8.1/10/2012r2/2016, but does
    # NOT have the vuln feature installed, so
    # reset previous finding.
    server_key = NULL;
    server_key_value = NULL;
    smb_v1_server_enabled = FALSE;
  }
}

# SMB Client
# key val '2' == automatic startup
# key val '3' == manual startup
# key val '4' == disabled
key = "SYSTEM\CurrentControlSet\Services\mrxsmb10\Start";
data = get_registry_value(handle:hklm, item:key);

if (data == 2 || data == 3) # manual (3) is default Vista SP0
{
  # Check if mrxsmb10 (SMBv1) is a dep
  # of lanmanWorkstation. If so, it's
  # in use and vuln.
  key2 = "SYSTEM\CurrentControlSet\services\LanmanWorkstation\DependOnService";
  data2 = get_registry_value(handle:hklm, item:key2);

  if ("mrxsmb10" >< tolower(data2))
  {
    client_key = key;
    client_key_value = data;
    client_deps_key = key2;

    # Be rid of nulls in deps string
    cdkv_len = strlen(data2);
    for (i=0; i<cdkv_len; i++)
      if (data2[i] == raw_string(0x00))
        data2[i] = ' ';

    client_deps_key_value = data2;
    smb_v1_client_enabled = TRUE;
  }
}

RegCloseKey(handle:hklm);
close_registry();

# Report
if (smb_v1_server_enabled || smb_v1_windows_feature_enabled || smb_v1_client_enabled)
{
  port = kb_smb_transport();

  if (smb_v1_server_enabled)
  {
    if (isnull(server_key_value)) server_key_value = 'NULL or missing';
    report += '\n' +
              '  SMBv1 server is enabled :' +
              '\n' +
              '    - HKLM\\'+server_key+' : '+server_key_value;
  }

  if (smb_v1_windows_feature_enabled)
  {
    report += '\n' +
              '  SMB1protocol feature is enabled based on the following key :' +
              '\n' +
              '    - HKLM\\'+smb_v1_windows_feature_key;
  }

  if (smb_v1_client_enabled)
  {
    if (isnull(client_key_value)) client_key_value = 'NULL or missing';
    report += '\n' +
              '  SMBv1 client is enabled :' +
              '\n' +
              '    - HKLM\\'+client_deps_key+' : '+client_deps_key_value +
              '\n' +
              '    - HKLM\\'+client_key+' : '+client_key_value;
  }

  report += '\n';

  security_report_v4(
    port:port,
    severity:SECURITY_NOTE,
    extra:report
  );
}
else audit(AUDIT_HOST_NOT, 'affected');
