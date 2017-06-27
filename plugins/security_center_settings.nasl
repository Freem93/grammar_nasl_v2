#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38687);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Microsoft Windows Security Center Settings");
  script_summary(english:"Checks Windows Security Center settings");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to audit Windows Security Center settings on the remote
system.");
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin enumerates Windows Security Center settings on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/883792");
 script_set_attribute(attribute:"solution", value:" Review the settings and ensure they are appropriate.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/05");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

AntiVirusDisableNotify = NULL ;
AntiVirusOverride = NULL;
FirewallDisableNotify = NULL;
FirewallOverride = NULL;
FirstRunDisabled = NULL;
UpdatesDisableNotify = NULL;
AntiSpywareOverride = NULL;

report = NULL;
settings = NULL;

key = "SOFTWARE\Microsoft\Security Center";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"AntiVirusDisableNotify");
  if (!isnull(value))
  {
   AntiVirusDisableNotify = value[1];
   settings += string( "AntiVirusDisableNotify : ",AntiVirusDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"AntiVirusOverride");
  if (!isnull(value))
  {
   AntiVirusOverride = value[1];
   settings += string("AntiVirusOverride : ", AntiVirusOverride,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirewallDisableNotify");
  if (!isnull(value))
  {
   FirewallDisableNotify = value[1];
   settings += string("FirewallDisableNotify : ",FirewallDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirewallOverride");
  if (!isnull(value))
  {
   FirewallOverride = value[1];
   settings += string("FirewallOverride : ",FirewallOverride,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirstRunDisabled");
  if (!isnull(value))
  {
   FirstRunDisabled = value[1];
   settings += string("FirstRunDisabled : ",FirstRunDisabled,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"UpdatesDisableNotify");
  if (!isnull(value))
  {
   UpdatesDisableNotify = value[1];
   settings += string("UpdatesDisableNotify : ",UpdatesDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"AntiSpywareOverride");
  if (!isnull(value))
  {
   AntiSpywareOverride = value[1];
   settings += string("AntiSpywareOverride : ",AntiSpywareOverride,"\n");
  }

  RegCloseKey(handle:key_h);
}

# In Vista, settings are stored here :

key = "SOFTWARE\Microsoft\Security Center\Svc";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"AntiVirusDisableNotify");
  if (!isnull(value) && isnull(AntiVirusDisableNotify))
  {
   AntiVirusDisableNotify = value[1];
   settings += string( "AntiVirusDisableNotify : ",AntiVirusDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"AntiVirusOverride");
  if (!isnull(value) && isnull(AntiVirusOverride))
  {
   AntiVirusOverride = value[1];
   settings += string("AntiVirusOverride : ", AntiVirusOverride,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirewallDisableNotify");
  if (!isnull(value) && isnull(FirewallDisableNotify))
  {
   FirewallDisableNotify = value[1];
   settings += string("FirewallDisableNotify : ",FirewallDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirewallOverride");
  if (!isnull(value) && isnull(FirewallOverride))
  {
   FirewallOverride = value[1];
   settings += string("FirewallOverride : ",FirewallOverride,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"FirstRunDisabled");
  if (!isnull(value) && isnull(FirstRunDisabled))
  {
   FirstRunDisabled = value[1];
   settings += string("FirstRunDisabled : ",FirstRunDisabled,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"UpdatesDisableNotify");
  if (!isnull(value) && isnull(UpdatesDisableNotify))
  {
   UpdatesDisableNotify = value[1];
   settings += string("UpdatesDisableNotify : ",UpdatesDisableNotify,"\n");
  }

  value = RegQueryValue(handle:key_h, item:"AntiSpywareOverride");
  if (!isnull(value) && isnull(AntiSpywareOverride))
  {
   AntiSpywareOverride = value[1];
   settings += string("AntiSpywareOverride : ",AntiSpywareOverride,"\n");
  }

  RegCloseKey(handle:key_h);
}

if(isnull(settings))
{
   NetUseDel();
   exit(0);
}

report += string("\nMicrosoft Windows Security Center is configured as follows : \n\n",
           settings,
           "\n");

key = "SOFTWARE\Microsoft\Security Center\Monitoring";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

monitor = NULL;

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey))
    {
      key2 = key + "\" + subkey;
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

      if(!isnull(key_h2))
      {
         value = RegQueryValue(handle:key_h2, item:"DisableMonitoring");
         value = value[1];

         if(!isnull(value) )
         {
           monitor += string(subkey, " appears to be installed.","\n");
         }
        RegCloseKey(handle:key_h2) ;
      }
    }
  }
  RegCloseKey(handle:key_h) ;
}

RegCloseKey(handle:hklm);

NetUseDel();

if(!isnull(monitor))
{
 report += string("Here's a list of antivirus / firewall software that may be installed :",
             "\n\n",
             monitor);
}

if(!isnull(report))
  security_note(port:port,extra:report);

