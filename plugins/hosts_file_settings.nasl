#TRUSTED 62a9f0acdbe7e691296bf94496f552f1990ac797e3ee396ac52df5de63fcafcab428fcbf0842bb672772097f1caf55fb44a65d45145331bfdc3f1821f8001ceb762429582af754cc6b11d9687ce20c36d38831680dbc7f4bbacd8436b0502f0ec230ba990e5396444bc7b4b800b17972ff17512f99c8c25f0dd287347ae06fff6df92a24e1b4cc2ca0be1941ee9673395b9d9c1b92a8c2f1ac49e09fd939701776e6151536a267bb9031665371743ef18b811ffa085b8e6ad741c9c983f0c3703c9bdc55fe733e765c7adc867cae3015ba8783fbd2b4a1f03c6de3cb0b7bb191ea63d03da114d7c135ce49de6d192e03473611a3d54ffd3775eeb6c04f23ba85a8b89b1e051c9918281197e914b97c171e4b42e5609f9f22ea3c92996f9471a8edc0453fb78beb08d2d58c9311bec3b870b03b4c54c40e8f2aaf0970b8dc3864d47f4e3899a6e25b042c608f0159d51f6c6da74e177d5db6d1d463ec8092b6edd169e1e5162ddfe693220de43403e303b8f8ecf219812c67b34e16ef555d002c3fc09b366eae9923039d49ca3aa84eefa95ea28f5413b66aecb1ad811710638b607b5fc9495008dff4d331162c04abd3e5773f05bad5c3c8329181750132d8a70984c98d360d6ff387dc49c6b4b102dd8ecbd8ce680ac74a2ec1d40a7c1813cd2cf542132368561ad7b42b0694e9d64ca0d3f3be6d57db75ffa66519047a421c
#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if (description)
{
  script_id(73980);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/13");

  script_name(english:"Hosts File Whitelisted Entries");
  script_summary(english:"Specify custom 'hosts' file entries to ignore.");

  script_set_attribute(attribute:"synopsis", value:"Specify custom 'hosts' file entries to ignore.");
  script_set_attribute(attribute:"description", value:
"This script allows entries in a customized 'hosts' file to be
whitelisted so that they are ignored by plugins that check for
abnormalities in the 'hosts' file.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/13");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_category(ACT_SETTINGS);

  script_add_preference(name:"Upload file with custom hosts entries : ", type:"file", value:"");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# from charset_func.inc
function get_ascii_printable(string)
{
  local_var asciiString, stringLen, i;

  stringLen = strlen(string);
  asciiString = "";
  for (i=0;i<stringLen;i++)
  {
    # 9=TAB, 10=LineFeed, 13=CarriageReturn
    # 32-126(0x20-0x7E) is the ascii printable range
    if (((ord(string[i]) > 31) && (ord(string[i]) < 127)) ||
         (ord(string[i]) == 9) || (ord(string[i]) == 10) ||
         (ord(string[i]) == 13) )
    {
      asciiString += string[i];
    }
  }

  return asciiString;
}

if (script_get_preference("Upload file with custom hosts entries : "))
  hosts_content = script_get_preference_file_content("Upload file with custom hosts entries : ");
else
  exit(0, "No hosts file.");

suspicious_hosts = make_list();
suspicious_hosts[0] = "kaspersky-labs.com";
suspicious_hosts[1] = "grisoft.com";
suspicious_hosts[2] = "symantec.com";
suspicious_hosts[3] = "sophos.com";
suspicious_hosts[4] = "mcafee.com";
suspicious_hosts[5] = "symantecliveupdate.com";
suspicious_hosts[6] = "viruslist.com";
suspicious_hosts[7] = "f-secure.com";
suspicious_hosts[8] = "kaspersky.com";
suspicious_hosts[9] = "avp.com";
suspicious_hosts[10] = "networkassociates.com";
suspicious_hosts[11] = "ca.com";
suspicious_hosts[12] = "my-etrust.com";
suspicious_hosts[13] = "nai.com";
suspicious_hosts[14] = "trendmicro.com";
suspicious_hosts[15] = "microsoft.com";
suspicious_hosts[16] = "virustotal.com";
suspicious_hosts[17] = "avp.ru";
suspicious_hosts[18] = "avp.ch";
suspicious_hosts[19] = "awaps.net";
suspicious_hosts[20] = "google.com";
suspicious_hosts[21] = "bing.com";
suspicious_hosts[22] = "yahoo.com";
suspicious_hosts[23] = "msn.com";

tmp = '';

# to save space in KB, only store entries which may generate false positives in a plugin
if (!isnull(hosts_content))
{
  # hosts file should be ASCII or UTF8, this will strip out BOMs and other
  # oddities text editors add
  hosts_content = get_ascii_printable(string:hosts_content);

  lines = split(hosts_content, sep:'\n', keep:FALSE);
  if(!isnull(lines))
  {
    foreach line(lines)
    {
      foreach host (suspicious_hosts)
      {
        if(host >< tolower(line))
        {
          tmp += line + '\n';
          break;
        }
      }
    }
  }
  if(tmp != '') set_kb_blob(name:"custom_hosts_contents", value:tmp);
}
else exit(0, "No hosts file content.");
