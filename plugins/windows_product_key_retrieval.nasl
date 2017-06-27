#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63620);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/18 20:20:22 $");

  script_name(english:"Windows Product Key Retrieval");
  script_summary(english:"Retrieves and decodes the Windows Product Key");

  script_set_attribute(attribute:"synopsis", value:
"This plugin retrieves the Windows Product key of the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to obtain the retrieve
the Windows host's partial product key'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("wmi_windows_partial_product_key.nbin", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

function base24decode(data) 
{
  local_var charArray, binaryArray, decodedString, index, value, i, j, k;
  charArray = make_list("B","C","D","F","G","H","J","K","M","P","Q","R","T","V","W","X","Y","2","3","4","6","7","8","9");
  binaryArray = NULL;
  decodedString = '';
  for(index=52; index<=66; index++)
  {
    value = ord(data[index]);
    if(isnull(binaryArray))
      binaryArray = make_list(value);
    else
      binaryArray = make_list(binaryArray, value);
  }
  for(i = 24; i >= 0; i--)
  {
    k = 0;
    for (j = 14; j >= 0; j--)
    {
      k = k * 256 ^ binaryArray[j];
      binaryArray[j] = k / 24;
      k = k % 24;
    }
    decodedString = charArray[k] + decodedString;
    if ((i % 5 == 0) && (i != 0 )) decodedString = '-' + decodedString;
  }
  return decodedString;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
ver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

partialProductKey = '';

# If earlier than Vista
if (ver_compare(ver:ver, fix:'6.0') == -1)
{
  registry_init();
  handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  subKey = "DigitalProductId";
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\" + subKey;
  digitalProductIdData = get_registry_value(handle:handle, item:key);
  RegCloseKey(handle:handle);
  close_registry();

  if (isnull(digitalProductIdData)) exit(1, "Failed to retrieve the " + subKey + " registry key.");

  productKey = base24decode(data:digitalProductIdData);
  partialProductKey = ereg_replace(pattern:"([0-9A-Z]{5}(?!$))", replace:"XXXXX", string:productKey);
  partialKey = split(partialProductKey, sep:'-');
  partialKey = partialKey[4];
  replace_kb_item(name:'Host/PartialProductKey', value:partialKey);
}
else 
{
  partialProductKey = get_kb_item_or_exit("Host/PartialProductKey");
  partialProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-" + partialProductKey;
}

port = kb_smb_transport();
if (report_verbosity > 0) 
{
   report = '\n  Product key : ' + partialProductKey + 
            '\n' +
            '\n' + 'Note that all but the final portion of the key has been obfuscated.' +
            '\n';
   security_note(port:port, extra:report);
}
else security_note(port);
