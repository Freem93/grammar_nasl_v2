#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27524);
  script_version("$Revision: 1.58 $");
  script_cvs_date("$Date: 2017/05/10 14:40:52 $");

  script_name(english:"Microsoft Office Detection");
  script_summary(english:"Detects the Microsoft Office version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an office suite.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://products.office.com/en-US/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
# version, sp, file version

i = 0;

# 2000 SP0
all_office_versions[i++] = make_list("Word", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("Excel", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2000", 0, "9.0.0.0");

# 2000 SP1 - no information

# 2000 SP2
all_office_versions[i++] = make_list("Word", "2000", 2, "9.0.0.4527");
all_office_versions[i++] = make_list("Excel", "2000", 2, "9.0.0.4430");
all_office_versions[i++] = make_list("PowerPoint", "2000", 2, "9.0.0.4527");

# 2000 SP3
all_office_versions[i++] = make_list("Word", "2000", 3, "9.0.0.6926");
all_office_versions[i++] = make_list("Excel", "2000", 3, "9.0.0.6627");
all_office_versions[i++] = make_list("PowerPoint", "2000", 3, "9.0.0.6620");

# XP SP0
all_office_versions[i++] = make_list("Word", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("Excel", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 0, "10.0.0.0");

# XP SP1
all_office_versions[i++] = make_list("Word", "XP", 1, "10.0.3416.0");
all_office_versions[i++] = make_list("Excel", "XP", 1, "10.0.3506.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 1, "10.0.3506.0");

# XP SP2
all_office_versions[i++] = make_list("Word", "XP", 2, "10.0.4219.0");
all_office_versions[i++] = make_list("Excel", "XP", 2, "10.0.4302.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 2, "10.0.4205.0");

# XP SP3
all_office_versions[i++] = make_list("Word", "XP", 3, "10.0.6612.0");
all_office_versions[i++] = make_list("Excel", "XP", 3, "10.0.6501.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 3, "10.0.6501.0");

# 2003 SP0
all_office_versions[i++] = make_list("Word", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("Excel", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 0, "11.0.0.0");

# 2003 SP1
all_office_versions[i++] = make_list("Word", "2003", 1, "11.0.6359.0");
all_office_versions[i++] = make_list("Excel", "2003", 1, "11.0.6355.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 1, "11.0.6361.0");

# 2003 SP2
all_office_versions[i++] = make_list("Word", "2003", 2, "11.0.6568.0");
all_office_versions[i++] = make_list("Excel", "2003", 2, "11.0.6560.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 2, "11.0.6564.0");

# 2003 SP3
all_office_versions[i++] = make_list("Word", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("Excel", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 3, "11.0.8169.0");

# 2007 SP0
all_office_versions[i++] = make_list("Word", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("Excel", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2007", 0, "12.0.0.0");

# 2007 SP1
all_office_versions[i++] = make_list("Word", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("Excel", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 1, "12.0.6215.1000");

# 2007 SP2
all_office_versions[i++] = make_list("Word", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("Excel", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 2, "12.0.6425.1000");

# 2007 SP3
all_office_versions[i++] = make_list("Word", "2007", 3, "12.0.6612.1000");
all_office_versions[i++] = make_list("Excel", "2007", 3, "12.0.6611.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 3, "12.0.6600.1000");

# 2010 SP0
all_office_versions[i++] = make_list("Word", "2010", 0, "14.0.4762.1000");
all_office_versions[i++] = make_list("Excel", "2010", 0, "14.0.4756.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 0, "14.0.4754.1000");

# 2010 SP1
all_office_versions[i++] = make_list("Word", "2010", 1, "14.0.6024.1000");
all_office_versions[i++] = make_list("Excel", "2010", 1, "14.0.6024.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 1, "14.0.6026.1000");

# 2010 SP2
all_office_versions[i++] = make_list("Word", "2010", 2, "14.0.7015.1000");
all_office_versions[i++] = make_list("Excel", "2010", 2, "14.0.7015.1000");
all_office_versions[i++] = make_list("PowerPoint", "2010", 2, "14.0.7015.1000");

# 2013
all_office_versions[i++] = make_list("Word", "2013", 0, "15.0.4420.1017");
all_office_versions[i++] = make_list("Excel", "2013", 0, "15.0.4420.1017");
all_office_versions[i++] = make_list("PowerPoint", "2013", 0, "15.0.4420.1017");

# 2013 SP1
all_office_versions[i++] = make_list("Word", "2013", 1, "15.0.4569.1504");
all_office_versions[i++] = make_list("Excel", "2013", 1, "15.0.4569.1504");
all_office_versions[i++] = make_list("PowerPoint", "2013", 1, "15.0.4454.1000");

# 2016 SP0
all_office_versions[i++] = make_list("Word", "2016", 0, "16.0.0.0");
all_office_versions[i++] = make_list("Excel", "2016", 0, "16.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2016", 0, "16.0.0.0");

# 2016 Click-to-Run versions
c2r_ver["4229"]=1509;
c2r_ver["6001"]=1509;
c2r_ver["6366"]=1511;
c2r_ver["6568"]=1601;
c2r_ver["6741"]=1602;
c2r_ver["6769"]=1603;
c2r_ver["6868"]=1604;
c2r_ver["6965"]=1605;
c2r_ver["7070"]=1606;
c2r_ver["7167"]=1607;
c2r_ver["7341"]=1608;
c2r_ver["7369"]=1609;
c2r_ver["7466"]=1610;
c2r_ver["7571"]=1611;
c2r_ver["7668"]=1612;
c2r_ver["7766"]=1701;
c2r_ver["7870"]=1702;
c2r_ver["7967"]=1703;

function check_version(v1, v2)
{
  local_var j;

  v1 = split(v1, sep:".", keep:FALSE);
  v2 = split(v2, sep:".", keep:FALSE);

  for (j=0; j<4; j++)
  {
   if (int(v1[j]) > int(v2[j]))
     return 1;
   else if (int(v1[j]) < int(v2[j]))
     return -1;
  }

  return 0;
}

version = NULL;
maj_version = NULL;
installed_office_versions = make_array();
installed_office_paths = make_array();
lowest_installed_prod = make_array();

products = make_list( "Word", "Excel", "PowerPoint" );
foreach product (products)
{
  kb = get_kb_list('SMB/Office/'+product+'/*/ProductPath');
  if ( isnull( kb ) )
    continue;

  foreach ver( keys(kb) )
  {
    key = ver;
    ver = ver - ('SMB/Office/'+product+'/');
    ver = ver - '/ProductPath';
    report_str = '  - ' + product + ' : ' + ver + '\n';
    prod_version = split( ver, sep:'.', keep:FALSE );
    maj_version = prod_version[0];
    if ( installed_office_versions[ maj_version ] )
    {
      installed_office_versions[ maj_version ] += report_str;
      if(ver_compare(ver:ver, fix:lowest_installed_prod[ maj_version ], strict:FALSE) < 0)
        lowest_installed_prod[ maj_version ] = ver;
    }
    else
    {
      installed_office_versions[ maj_version ] = report_str;
      lowest_installed_prod[ maj_version ] = ver;
    }

    if ( !installed_office_paths[ maj_version ])
    {
      installed_office_paths[ maj_version ] = ereg_replace(pattern:'^(.*)\\\\.*', replace:"\1\", string:kb[key]);
    }
  }
}

# Find update channel, channel version, and channel build for Office 2016
# https://technet.microsoft.com/en-us/library/mt592918.aspx#BKMK_ByDate

product_list = get_kb_list("SMB/Office/*/*/ProductPath");
# Example: SMB/Office/Word/16.0.6001.1073/ProductPath=[path]
pattern = '^SMB/Office/([A-Za-z]+)/([0-9.]+)/ProductPath$';

channel         = NULL;
channel_version = NULL;
channel_build   = NULL;

office_c2r_version = NULL;
office_c2r_build   = NULL;
office_c2r_channel = NULL;

supported_versions = make_array();

foreach product_kb (keys(product_list))
{
  unsupported_date = NULL;
  fields = eregmatch(pattern:pattern, string:product_kb, icase:TRUE);
  full_version = fields[2];
  if ( ! (full_version =~ '^16\\.0') ) continue;
  product_name = fields[1];

  ver_parts = split(full_version, sep:'.', keep:FALSE);

  # If product is an MSI install, we don't need to check channel version / channel build info
  if (ver_parts[2] >= 4288 && ver_parts[2] < 6001)
  {
    channel = "MSI";
    set_kb_item(name:"SMB/Office/"+product_name+"/16.0/Channel", value:channel);
    if ( product_name == "Word" || product_name == "Excel" )
      office_c2r_channel = channel;
    continue;
  }

  # Third part of full_version correlates to the channel "Version"
  channel_version = c2r_ver[ver_parts[2]];
  if (empty_or_null(channel_version)) channel_version = "unknown";
  channel_build = ver_parts[2] + "." + ver_parts[3];

  # Determine channel based on version
  # Builds that appear in both First Release for Deferred and another branch default to the other branch
  #
  # This is updated whenever:
  # - A channel_version that is simultaneously being released to both Current and First Release for Deferred stops
  #   being released to the Current channel and is only being released to the First Release for Deferred channel
  # - A channel_version that is being updated for the First Release for Deferred channel is released to the Deferred
  #   channel and a new channel_version starts being released to the First Release for Deferred channel

  # Supported Channel versions
  supported_versions["Current"] = "1703"; # last security update
  supported_versions["First Release for Deferred"] = "1701";
  supported_versions["Deferred"] = "1605 / 1609";

  if ( channel_version == "1509" )
  {
    if (ver_parts[3] <= 1043) channel = "Current";
    else if (ver_parts[3] == 1054) channel = "First Release for Deferred";
    else channel = "Deferred";
  }
  else if ( channel_version == "1602" )
  {
    if (ver_parts[3] == 2017 || ver_parts[3] == 2021) channel = "Current";
    else if (ver_parts[3] <= 2047) channel = "First Release for Deferred";
    else channel = "Deferred";
  }
  else if ( channel_version == "1605" )
  {
    if (ver_parts[3] <= 2063) channel = "Current";
    else if (ver_parts[3] <= 2084) channel = "First Release for Deferred";
    else channel = "Deferred";
  }
  else if ( channel_version == "1609" )
  {
    if (ver_parts[3] <= 2055) channel = "Current";
    else if (ver_parts[3] <= 2102) channel = "First Release for Deferred";
    else channel = "Deferred";
  }
  else if ( channel_version == "1701" )
  {
    if (ver_parts[3] <= 2060) channel = "Current";
    else channel = "First Release for Deferred";
  }
  else
    channel = "Current";

  if (!get_kb_item("SMB/Office/365")) set_kb_item(name:"SMB/Office/365", value:TRUE);

  # By this point we have :
  # - path
  # - channel
  # Add channel to installed_sw/ data where possible
  if ("Lync" >< product_kb)
  {
    short_path = ereg_replace(string:product_list[product_kb], pattern:"^(.*\\)[^/]+$", replace:"\1");
    app_kb_key = make_app_kb_key(app_name:'Microsoft Lync');
    if (app_kb_key[0] == IF_OK)
    {
      install_kb_key = make_install_kb_key(app_kb_key:app_kb_key[1], path:short_path);
      if (install_kb_key[0] == IF_OK)
        add_extra_to_kb(install_kb_key:install_kb_key[1], extra:make_array('Channel', channel));
    }
  }

  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/Channel", value:channel);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelVersion", value:channel_version);
  set_kb_item(name:"SMB/Office/"+product_name+"/16.0/ChannelBuild", value:channel_build);
  if (!empty_or_null(supported_versions[channel]))
    set_kb_item(name:"SMB/Office/"+product_name+"/16.0/SupportedVersions", value:supported_versions[channel]);

  if ( product_name == "Word" || product_name == "Excel" )
  {
    office_c2r_channel = channel;
    office_c2r_version = channel_version;
    office_c2r_build   = channel_build;
  }
}
# If we found Office 2016 products but were not able to set Office channel based on Word/Excel, use last product
if ( channel && !office_c2r_channel )
{
  office_c2r_channel = channel;
  if (channel != "MSI")
  {
    office_c2r_version = channel_version;
    office_c2r_build   = channel_build;
  }
}

if (office_c2r_channel)
{
  if (!get_kb_item("SMB/Office/365")) set_kb_item(name:"SMB/Office/365", value:TRUE);

  set_kb_item(name:"SMB/Office/16.0/Channel", value:office_c2r_channel);
  if (!empty_or_null(supported_versions[channel]))
    set_kb_item(name:"SMB/Office/16.0/SupportedVersions", value:supported_versions[channel]);

  if (office_c2r_channel != "MSI")
  {
    set_kb_item(name:"SMB/Office/16.0/ChannelVersion", value:office_c2r_version);
    set_kb_item(name:"SMB/Office/16.0/ChannelBuild", value:office_c2r_build);
    channel_text =
    '\n  Office 2016 Click-to-Run update channel : ' + office_c2r_channel +
    '\n  Office 2016 Click-to-Run version        : ' + office_c2r_version +
    '\n  Office 2016 Click-to-Run build          : ' + office_c2r_build +
    '\n';
  }
}

kb_blob = 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName';
installed_products_by_uuid = get_kb_list( kb_blob );

foreach uuid ( keys( installed_products_by_uuid ) )
{
  if ( ( installed_products_by_uuid[ uuid ] =~ '^Microsoft Office (2000|XP|[a-zA-Z ]*?(Edition|20[01][0-9])|365)' ) &&
       ( ! ereg( pattern:"(Media Content|Get Started|Proof|MUI|Communicator|InfoPath|Web Components|Viewer|Primary Interop Assemblies|Access ([0-9]+ )?Runtime|Access database engine|Office [0-9]+ Resource Kit|Visio|OneNote|SharePoint|Project Professional|Project Standard|Visual Web Developer|Interface Pack|Deployment Kit for App-V)",
                 string:installed_products_by_uuid[ uuid ], icase:TRUE ) ) &&
       ('FrontPage' >!< installed_products_by_uuid[uuid] || 'with FrontPage' >< installed_products_by_uuid[uuid]) )
  {
    path = get_kb_item ( str_replace( string:uuid, find:'DisplayName', replace:'InstallLocation'));
    kb = get_kb_item( str_replace( string:uuid, find:'DisplayName', replace:'DisplayVersion' ) );
    if ( isnull( kb ) )
      continue;

    office_version = split( kb, sep:'.', keep:FALSE );
    office_maj_version = office_version[0];

    # Check the registry entry against the actual file versions of found product installs
    # go with the file versions (more accurate) if the reg key is lower.
    if (ver_compare(ver:kb, fix:lowest_installed_prod[office_maj_version], strict:FALSE) < 0)
      kb = lowest_installed_prod[office_maj_version];

    if ('The remote host has the following' >< installed_office_versions[office_maj_version])
      continue;
    if (path >!< installed_office_paths[office_maj_version])
      continue;

    prod_detail = installed_office_versions[office_maj_version];
    if (prod_detail && ! empty_or_null(prod_detail))
    {
      len = max_index(all_office_versions);
      for (i=0; i<len; i++)
      {
        info = all_office_versions[i];
        if (check_version(v1:kb, v2:info[3]) >= 0)
          version = i;
      }
      info = all_office_versions[version];
      report_detail = '\nThe remote host has the following Microsoft Office '+ info[1]+ ' Service Pack '+ info[2]+' component';

      if ( max_index( split( prod_detail ) ) > 1)
        report_detail += 's';

      report_detail += ' installed :\n\n';
      installed_office_versions[office_maj_version] = report_detail + prod_detail;
      set_kb_item(name:"SMB/Office/"+info[1]+"/SP", value:info[2]);

      # Save product code.
      code_pattern = "SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/\{([\w-]+)\}\/DisplayName";
      match = eregmatch(string:uuid, pattern:code_pattern, icase:TRUE);
      if (!isnull(match))
        set_kb_item(name:"SMB/Office/"+info[1]+"/IdentifyingNumber", value:match[1]);
    }
  }
}

if (max_index(keys(installed_office_versions)) == 0)
 exit(0, "No instances of Office were found.");

if (installed_office_versions["16"] && channel_text)
  installed_office_versions["16"] += channel_text;

report = NULL;
foreach key ( keys( installed_office_versions ) )
  report += installed_office_versions[ key ];

security_note(port:0, extra:report);
