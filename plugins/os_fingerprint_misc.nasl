#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65765);
  script_version("$Revision: 2.16 $");
  script_cvs_date("$Date: 2015/07/01 15:29:45 $");

  script_name(english:"OS Identification : Miscellaneous Methods");
  script_summary(english:"Identifies devices based on miscellaneous methods.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on
miscellaneous information.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified via miscellaneous
sources of information.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("bigip_web_detect.nasl", "hp_laserjet_detect.nasl", "packeteer_web_detect.nasl", "smb_nativelanman.nasl", "veritas_agent_detect.nasl", "wdb_agent_detect.nasl",
                      "hp_lefthand_console_discovery.nasl", "hp_lefthand_hydra_detect.nasl", "hp_saniq_hydra_detect.nbin", "hp_data_protector_module_versions.nbin");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


function convert_win_ver_to_name(ver, sp)
{
  local_var os, os1, os2;

  os = "";
  if (ver == "4.0")
    os = "Microsoft Windows NT 4.0";
  else if (ver == "5.0")
    os = 'Microsoft Windows 2000\nNetApp';
  else if (ver == "5.1")
    os = 'Microsoft Windows XP\nMicrosoft Windows XP for Embedded Systems';
  else if (ver == "5.2")
    os = "Microsoft Windows Server 2003";
  else if (ver == "6.0")
    os = 'Microsoft Windows Vista\nMicrosoft Windows Server 2008';
  else if (ver == "6.1")
    os = 'Microsoft Windows 7\nMicrosoft Windows Server 2008 R2';
  else if (ver == "6.2")
    os = 'Microsoft Windows 8\nMicrosoft Windows Server 2012';
  else if (ver == "6.3")
    os = 'Microsoft Windows 8.1\nMicrosoft Windows Server 2012 R2\nMicrosoft Windows 10 Enterprise Insider Preview';

  if (os && sp)
  {
    os2 = "";
    foreach os1 (split(os, keep:FALSE))
    {
      os2 += os1 + ' Service Pack ' + sp + '\n';
    }
    os = chomp(os2);
  }

  return os;
}

kb_base = "Host/OS/Misc";              # nb: should *not* end with a slash

if (
  get_kb_item("Services/cpfw1") ||
  get_kb_item("Services/fw1_generic") ||
  get_kb_item("Services/cp_ica")
)
{
  set_kb_item(name:kb_base, value:"Check Point GAiA");
  set_kb_item(name:kb_base+"/Confidence", value:70);
  set_kb_item(name:kb_base+"/Type", value:"firewall");
}

item = get_kb_item("www/hp_laserjet/pname");
if (!isnull(item))
{
  match = eregmatch(pattern:'^(HP (Color LaserJet|Digital Sender|LaserJet) [A-Za-z0-9]+)', string:item);
  if (match)
  {
    os = match[1];

    item2 = get_kb_item("www/hp_laserjet/fw");
    if (!isnull(item2))
    {
      match2 = eregmatch(pattern:'([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)', string:item2);
      if (match2) os += ' with firmware version ' + match2[1];
    }

    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:99);
    set_kb_item(name:kb_base+"/Type", value:"printer");
    exit(0);
  }
}

item = get_kb_item("www/bigip");
if (!isnull(item))
{
  set_kb_item(name:kb_base, value:"F5 Networks BIG-IP");
  set_kb_item(name:kb_base+"/Confidence", value:75);
  set_kb_item(name:kb_base+"/Type", value:"load-balancer");
}

xnm_list = get_kb_list("Services/xnm");
if (!isnull(xnm_list))
{
  # nb: we should need the banner from just one of these.
  foreach p (xnm_list)
  {
    b = get_kb_item("xnm/banner/"+p);
    if (!isnull(b))
    {
      match = eregmatch(pattern:'os="JUNOS" release="([0-9][^"]+)" hostname=', string:b);
      if (!isnull(match))
      {
        os = "Juniper Junos Version " + match[1];

        set_kb_item(name:kb_base, value:os);
        set_kb_item(name:kb_base+"/Confidence", value:95);
        set_kb_item(name:kb_base+"/Type", value:"embedded");
        exit(0);
      }
    }
  }
}

item = get_kb_item("www/443/packeteer");
if (!isnull(item) && "PacketShaper" == item)
{
  set_kb_item(name:kb_base, value:"Blue Coat PacketShaper");
  set_kb_item(name:kb_base+"/Confidence", value:75);
  set_kb_item(name:kb_base+"/Type", value:"embedded");
}

item = get_kb_item("Host/Veritas/BackupExecAgent/OS_Type");
if (!isnull(item))
{
  item2 = get_kb_item("Host/Veritas/BackupExecAgent/OS_Version");
  if ("Windows" >< item && "Major Version=" >< item2)
  {
    match = eregmatch(pattern:'Major Version=([0-9]+) Minor Version=([0-9]+) Build Number=([0-9]+) ServicePack Major=([0-9]+) ServicePack Minor=([0-9]+) SuiteMask=([0-9]+) ProductType=([0-9]+) ProcessorType=(.+)$', string:item2);
    if (!isnull(match))
    {
      os = convert_win_ver_to_name(ver:match[1]+"."+match[2], sp:int(match[4]));
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"embedded");
      exit(0);
    }
  }
}

item = get_kb_item("Host/OS/smb");
if (!isnull(item))
{
  if ("EMC-SNAS" >< item)
  {
    set_kb_item(name:kb_base, value:"EMC Celerra File Server");
    set_kb_item(name:kb_base+"/Confidence", value:95);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0);
  }
  else if ("Windows " >< item)
  {
    item = chomp(item) - "Windows ";
    os = convert_win_ver_to_name(ver:item);
    if ("Windows " >< os)
    {
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }
}

item = get_kb_item("Host/VxWorks/RunTimeVersion");
if (!isnull(item))
{
  if ("VxWorks" >< item)
  {
    os = "VxWorks";

    match = eregmatch(pattern:'VxWorks[ \t]*([0-9][0-9.]+)', string:item);
    if (!isnull(match)) os += ' ' + match[1];

    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:70);
    set_kb_item(name:kb_base+"/Type", value:"embedded");
    exit(0);
  }
}

item = get_kb_item("HP/LeftHandOS");
if(!isnull(item))
{
  set_kb_item(name:kb_base, value:"HP LeftHand OS");
  set_kb_item(name:kb_base+"/Confidence", value:99);
  set_kb_item(name:kb_base+"/Type", value:"embedded");
  exit(0);
}

# HP Data Protector puts OS information in patch info string
# e.g -os "microsoft i386 wNT-5.2-S"
item = get_kb_item("Services/data_protector/patch_info_str");
res = eregmatch(pattern:'-[oO][sS] "([^"]+)"', string:item);
if (isnull(res))
{
  item = get_kb_item("Services/data_protector/patch_info_is_str");
  res = eregmatch(pattern:'-[oO][sS] "([^"]+)"', string:item);
}

if (!isnull(res))
{
  os_str = tolower(res[1]);

  # Windows
  # microsoft i386 wNT-5.2-S
  item = eregmatch(pattern:"^microsoft .+ wnt-([0-9.]+)-[swu]$", string:os_str);
  if (!isnull(item) && !isnull(item[1]))
  {
    os = convert_win_ver_to_name(ver:item[1]);
    if (os != "")
    {
      confidence = 80;
      if ('\n' >< os) confidence -= 10;

      set_kb_item(name:kb_base, value:os);
      set_kb_item(name:kb_base+"/Confidence", value:confidence);
      set_kb_item(name:kb_base+"/Type", value:"general-purpose");
      exit(0);
    }
  }

  # Linux
  # gpl x86_64 linux-2.6.18-194.el5
  item = eregmatch(pattern:"^gpl .+ linux-([0-9.]+)([^0-9.].*)?$", string:os_str);
  if (!isnull(item))
  {
    os = "Linux Kernel " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }

  # HP-UX
  # hp s800 hp-ux-11.00
  item = eregmatch(pattern:"^hp .+ hp-ux-([0-9.]+)$", string:os_str);
  if (!isnull(item))
  {
    os = "HP-UX " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }

  # Solaris
  # sun sparc solaris-5.8
  item = eregmatch(pattern:"^sun .+ solaris-([0-9.]+)$", string:os_str);
  if (!isnull(item))
  {
    os = "Solaris " + item[1];
    confidence = 70;
    set_kb_item(name:kb_base, value:os);
    set_kb_item(name:kb_base+"/Confidence", value:confidence);
    set_kb_item(name:kb_base+"/Type", value:"general-purpose");
    exit(0);
  }
}

exit(0, "Nessus was not able to identify the OS from miscellaneous methods.");
