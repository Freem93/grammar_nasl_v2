#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25246);
  script_version("$Revision: 1.173 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : SNMP");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on the
SNMP data returned.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the operating system type and version by
examining the SNMP data returned by the remote server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/sysDesc");

  exit(0);
}

name = get_kb_item("SNMP/sysName");

if ( ( os = get_kb_item("SNMP/sysDesc")) )
{
 set_kb_item(name:"Host/OS/SNMP/Fingerprint", value:os);

 # Fedora 23, 24, 25, ...
  if (os =~ "^Linux [^ ]+ (\d+\.\d+).*\.fc(2[0-9])\.(i686|x86_64).*(i686|x86_64)$")
  {
    matches = eregmatch(
      pattern:"^Linux [^ ]+ (\d+\.\d+).*\.fc(2[0-9])\.(i686|x86_64).*(i686|x86_64)$",
      string:os
    );

    if (!matches)
      exit(1, "Version could not be parsed from SNMP/sysDesc '"+os+"'.");
    else
      fedora_version = 'Linux Kernel ' + matches[1] + ' on Fedora release ' + matches[2];

    set_kb_item(name:"Host/OS/SNMP", value:fedora_version);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
    exit(0);
  }

  # Virtuozzo x.x, ...
  # 7.3 :
  # Linux localhost.localdomain 3.10.0-327.36.1.vz7.20.18 #1 SMP Tue Dec 20 13:52:43 MSK 2016 x86_64
  # 7.2 :
  # Linux localhost.localdomain 3.10.0-327.18.2.vz7.15.2 #1 SMP Fri Jul 22 14:48:06 MSK 2016 x86_64
  if (os =~ "^Linux [^ ]+ (\d+\.\d+).*\.vz(\d+)\.([0-9.]+) .*(i686|x86_64)$")
  {
    matches = eregmatch(
      pattern:"^Linux [^ ]+ (\d+\.\d+).*\.vz(\d+)\.([0-9.]+) .*(i686|x86_64)$",
      string:os
    );

    if (!matches)
      exit(1, "Version could not be parsed from SNMP/sysDesc '"+os+"'.");
    else
    {
      conf = 98;
      # Virtuozzo 7.3
      if (matches[3] == "20.18")
        virtuozzo_version = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release 7.3';
      # Virtuozzo 7.2
      else if (matches[3] == "15.2")
        virtuozzo_version = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release 7.2';
      else
      {
        virtuozzo_version = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release ' + matches[2];
        conf = 70;
      }
    }

    set_kb_item(name:"Host/OS/SNMP", value:virtuozzo_version);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:conf);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
    exit(0);
  }

 # ADSL2+ Modem Version 3.08.02.IB.02.01_1701_02270
 if (os =~ "^ADSL2\+ Modem Version [0-9A-Z_.+] *$" &&
     name == "DNA-A211-I")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Semindia DNA-A211-I Wireless DSL Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }
 if ( "Siemens" >< os )
 {
  value = "Siemens Device";
  type = "embedded";
  conf = 80;
  if (os =~ "^Siemens Subscriber Networks [0-9]*-Series")
  {
    value = "Siemens SpeedStream Router";
    type = "router";
    conf = 100;
  }
  else
  {
    match = eregmatch(string:os, pattern:"AG SIMOTION ([A-Z])([^a-zA-Z]| |$)");
    if (!isnull(match))
    {
      if (match[1] == "D") value = "Siemens Drive Controller";
      else if (match[1] == "C") value = "Siemens Card Controller";
      else if (match[1] == "P") value = "Siemens Motion Controller";
      conf = 95;
    }
  }
  set_kb_item(name:"Host/OS/SNMP", value:value);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:conf);
  set_kb_item(name:"Host/OS/SNMP/Type", value:type);
  exit(0);
 }
 if ( os =~ "^eCos " )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"eCos Embedded Operating System");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "Alpine380[48]" )
 {
 if ( "3804" >< os )
   set_kb_item(name:"Host/OS/SNMP", value:"Extreme Networks Alpine 3804 Switch");
 else
   set_kb_item(name:"Host/OS/SNMP", value:"Extreme Networks Alpine 3808 Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if (  "HUAWEI-3COM WBR-204g" >< os  )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Huawei-3com WBR-204g");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }
 if ("Huawei" >< os && os =~ "VRP(?: \(R\))? [sS]oftware,\s*Version (\d(?:\.\d+)*)")
 {
  match = eregmatch(pattern:"VRP(?: \(R\))? [sS]oftware,\s*Version (\d(?:\.\d+)*)", string:os);
  os = "Huawei Versatile Routing Platform";
  if (!isnull(match)) os += ' ' + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ("Wireless ADSL WLAN" >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"arcadyan wireless ADSL router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 20);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ( os =~ "^MAP-330 - Hardware revision" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Colubris MAP-330 AP");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

# Netgear Wireless Cable Voice Gateway <<HW_REV: V1.0; VENDOR: Netgear; BOOTR: 2.1.7i; SW_REV: 3.9.21.5.RHE00157; MODEL: CBVG834G>>
 if ("Netgear Wireless Cable Voice Gateway" >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Netgear Cable Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }

 if (match = eregmatch(pattern:"^(GSM?[0-9]+T[A-Z]*)v[0-9]+$", string:os))
 {
  os = "Netgear " + match[1] + " Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ( os =~ "^Prestige ([0-9A-Za-z]*|[-/ ]*)*$" ||
      os =~ "^P-[0-9A-Z]*-[0-9A-Z]*( V[0-9]+)?$" )
 {
  if ( os =~ "^P-" )
	os = ereg_replace(pattern:"^P-", replace:"Prestige ", string:os);
  os = "ZyXEL " + chomp(os) + " ADSL Router";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( "Redback Networks SmartEdge OS Version SEOS-" >< os )
 {
  os = egrep(pattern:"^Redback Networks SmartEdge OS Version", string:os);
  os = ereg_replace(pattern:".*SmartEdge OS Version SEOS-(.*)\.Built.*", replace:"SmartEdge OS \1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }

 if ( "Raritan Computer; CommandCenter Secure Gateway" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Raritan CommandCenter Secure Gateway KVM");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ( "Raritan Dominion PX" >< os )
 {
  match = eregmatch(pattern:"Raritan Dominion PX - Firmware Version ([0-9]+-[0-9])", string:os);
  os = "Raritan Dominion PX";
  if (match) os += " with Firmware Version " + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ( os =~"FreeBSD.* FreeBSD " || os =~ "Software: FreeBSD")
 {
  os = chomp(ereg_replace(pattern:".*(FreeBSD [0-9.]+[^ ]*).*",string:os, replace:"\1"));
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }

 if ( os =~ "VerAg:[0-9._]*;VerSw:[0-9._]*;VerHw:MXe;VerPl:" )
 {
  os = "Mitel Networks PBX Server";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"pbx");
  exit(0);
 }
 if ( os =~ "Foundry Networks.*IronWare Version [^ ]*.*" )
 {
  os = "Foundry Networks IronWare " + ereg_replace(pattern:".*IronWare Version ([^ ]*) .*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "ZyWALL" >< os )
 {
  os = "ZyXEL ZyWALL Security Appliance";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
  exit(0);
 }
 if ( "Lexmark" >< os )
 {
  os = "Lexmark Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Integrated PrintNet Enterprise Version" >< os )
 {
  os = "Printronix Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if (os =~ "Samsung (CL[PX]|ML|SCX)-[0-9][0-9_]+( Series|; OS )")
 {
  os = ereg_replace(pattern:".*(Samsung (CL[PX]|ML|SCX)-[0-9][0-9_]+)( Series|; OS ).*", replace:"\1 Series Printer", string:os);
  os = chomp(os);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ("Dell Force10 Real Time Operating System" >< os)
 {
  os = "Dell Force10 Operating System";
  match = eregmatch(pattern:"Dell Force10 Operating System Version: ([0-9][0-9.]+)", string:os);
  if (!isnull(match)) os += " " + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "This system component provides a complete set of remote management functions for a Server" >< os )
 {
  os = "Dell Remote Access Controller";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Fiery " >< os )
 {
  os = "Minolta Fiery Copier";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "TOSHIBA e-STUDIO" >< os )
 {
  ver = ereg_replace(pattern:".*TOSHIBA e-STUDIO([0-9]+).*", string:os, replace:"\1");
  if ( ver == os ) ver = NULL;
  os = "Toshiba e-Studio " + ver + " printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Dell Out-of-band SNMP" >< os )
 {
  os = "Dell Remote Access Controller";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "^Dell [0-9]+(cn?|cdn|cnw|dn?|)[; ].+Engine")
 {
  match = eregmatch(pattern:"^Dell ([0-9]+)(cn?|cdn|cnw|dn?)[; ]", string:os);
  if (match[2] =~ "^c") os = strcat("Dell ", match[1], match[2], " Color Laser Printer");
  else os = strcat("Dell ", match[1], match[2], " Laser Printer");

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Dell Color Laser " >< os || "Dell 3130cn Color Laser" >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Dell Color Laser Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "^2161DS-[0-9] [0-9.]+$" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Dell KVM 2161DS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Dell Laser " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Dell Laser Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( "3Com Switch" >< os )
 {
  match = eregmatch(pattern:"^3Com Switch ([0-9][^ ]+ [0-9]+-Port) Software Version 3Com OS (V[0-9][0-9.a-z]+)", string:os);
  if (isnull(match)) os = "3Com Switch";
  else os = "3Com " + match[1] + " Switch with firmware " + match[2];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "3Com SuperStack " >< os )
 {
  os = "3Com SuperStack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "3Com SuperStackII " >< os )
 {
  os = "3Com SuperStack II switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "3Com Baseline " >< os)
 {
   os = "3Com Baseline Switch";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if ("TigerStack" >< os )
 {
  os = "SMC TigerStack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "Bay Stack.*hub" )
 {
  os = "Nortel Bay Stack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if (
  os =~ "Ethernet (Routing )?Switch.*Nortel Network" ||
  os =~ "^BayStack "
 )
 {
  os = "Nortel Ethernet Routing Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if (os =~ "CS [0-9]+.*Call Server.*Nortel" )
 {
  item = eregmatch(pattern:'(CS [0-9][^"]+)" SW', string:os);
  if (isnull(item)) os_name = "Nortel Call Server";
  else os_name = "Nortel " + item[1] + " Call Server";

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "^Nortel, CS [0-9]+ Signaling Server" ||
      os =~ "CS [0-9]+.*Signaling Server.*Nortel" )
 {
  os = "Nortel CS Signaling Server";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "^Nortel SR ")
 {
  os_name = "Nortel Secure Router";

  item = eregmatch(pattern:"^Nortel SR ([0-9][^ ,]+),", string:os);
  if (!isnull(item)) os_name += " " + item[1];

  item = eregmatch(pattern:"Software Version = r([0-9][^ ,]+)", string:os);
  if (!isnull(item)) os_name += " with software release " + item[1];

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if (os =~ "CS [0-9]+.*VGMC.*Nortel" )
 {
  # Nortel IP Line and Voice Gateway Media Card
  item = eregmatch(pattern:'MC Firmware Rls ([0-9][0-9.]+)', string:os);
  if (isnull(item)) os_name = "Nortel VGMC";
  else os_name = "Nortel VGMC with firmware " + item[1];

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Dell Laser Printer " >< os )
 {
  os = "Dell Laser Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Prisma Digital Transport" >< os )
 {
   os = "Prisma Digital Transport System";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ( "RICOH Network Printer C model" >< os )
 {
   os = "Ricoh Printer";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
 }
 if ( "CMTS" >< os && "Juniper Networks Inc." >< os )
 {
   os = "Juniper CMTS";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("Chkpoint/LTX" >< os )
 {
   os = "Check Point/Lantronix Network Adaptor";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("Konica IP Controller" >< os )
  {
   os = "Konica IP Controller";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
  }
 if ("Marconi ASX" >< os )
  {
   os = "Marconi ASX Switch";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
  }
 if ("CoreBuilder 3500" >< os )
  {
   os = "3Com CoreBuilder 3500 Switch";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
  }
 if ("Ascend Max-HP" >< os )
  {
   version = ereg_replace(pattern:"Software \+([0-9.]*)\+.*", string:os, replace:"\1");
   os = "Ascend Max-HP Modem Hub " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
  }
  if ( "HP StorageWorks " >< os )
  {
   set_kb_item(name:"Host/OS/SNMP", value:"HP StorageWorks");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
  }
 if ("LVisual UpTime Multiprotocol T1 CSU DROP & INSERT ASE Ver" >< os )
 {
   version = ereg_replace(pattern:".* ASE Ver ([0-9.]*) .*", string:os, replace:"\1");
   os = "Visual Networks ASE " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("ELSA LANCOM" >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
   exit(0);
 }
 if ("IP Console Switch " >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"HP " + os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if (ereg(pattern:"^HP [^ ]+ Switch", string:os))
 {
   os = ereg_replace(pattern:"^(HP [^ ]+ Switch).*", string:os, replace:"\1");
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }
 if ("SCO UnixWare" >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }
 if ( "SCO TCP/IP Runtime Release " >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"SCO OpenServer");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ("Apple Base Station" >< os )
 {
   version = ereg_replace(pattern:".*Apple Base Station V(.*) Compatible",
			  replace:"\1",
			  string:os);

   os = "Apple Airport " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
   exit(0);
 }

 if ( "Apple AirPort" >< os )
 {
  os = "Apple AirPort Extreme Base Station";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ("OpenVMS" >< os )
 {
  version = ereg_replace(pattern:".*OpenVMS V([0-9]*\.[0-9]*).*",
			 string:egrep(pattern:"OpenVMS", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "OpenVMS " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }


 }
 if ("IBM Gigabit Ethernet Switch Module" >< os )
 {
   os = "IBM Gigabit Ethernet Switch Module";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if (os =~ "^Panasonic DP-[A-Z0-9]+")
 {
  os = ereg_replace(pattern:"Panasonic (DP-[A-Z0-9]+)", replace:"\1 Digital Imaging System", string:os);
  os = chomp(os);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if (os =~ "^WJ-HD300 SWVer[0-9]\.[0-9]+")
 {
   os = strcat("Panasonic Digital ", os);
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 100);
   set_kb_item(name:"Host/OS/SNMP/Type", value: "embedded");
   exit(0);
 }

 if (os == "Ultrium Tape Library Specialist")
 {
   os = "IBM Ultrium Table Library";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 99);
   set_kb_item(name:"Host/OS/SNMP/Type", value: "embedded");
   exit(0);
 }

 if ( os =~ "^Cisco Identity Services Engine")
 {
   os = "Cisco Identity Services Engine";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 99);
   set_kb_item(name:"Host/OS/SNMP/Type", value: "general-purpose");
   exit(0);
 }

 if ( os =~ "^Cisco Adaptive Security Appliance Version" )
 {
   v = ereg_replace(pattern:"^Cisco Adaptive Security Appliance Version ([0-9().]+)$", string:os, replace:"\1");
   if ( v && v != os )
   {
    set_kb_item(name:"Host/OS/SNMP", value:"CISCO ASA Version " + chomp(v));
    set_kb_item(name:"Host/OS/SNMP/Confidence", value: 99);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   }
   else
   {
    set_kb_item(name:"Host/OS/SNMP", value:"CISCO ASA");
    set_kb_item(name:"Host/OS/SNMP/Confidence", value: 98);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   }
   exit(0);
 }
 if ( os =~ "^Cisco Controller" )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"Cisco Wireless Controller");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
   exit(0);
 }
 if ( "IOS (tm)" >< os  || "Cisco IOS Software" >< os )
 {
  version = ereg_replace(pattern:".*IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),.*",
			 string:egrep(pattern:"IOS", string:os),
			 replace:"\1");

  if ( version != os )
  {
   if ('IOS-XE' >< os)
     os = "Cisco IOS XE " + version;
   else
     os = "CISCO IOS " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
   exit(0);
  }
 }
 # eg, Cisco Cisco PIX Security Appliance Version 8.0(4)28
 if ("Cisco PIX" >< os)
 {
   v = eregmatch(pattern:"Cisco PIX Security Appliance Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*)", string:os);
   os = "CISCO PIX";
   if (!isnull(v)) os += strcat(" ", v[1]);

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
   exit(0);
 }

 if ("Cisco Systems, Inc./VPN 3000 Concentrator " >< os)
 {
   v = eregmatch(string: os, pattern: "^Cisco Systems, Inc./VPN 3000 Concentrator Version ([0-9]\.[0-9A-Z.]+)");
   if (isnull(v))
     os = "CISCO VPN Concentrator";
   else
     os = strcat("CISCO VPN Concentrator Version ", v[1]);
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"VPN");
   exit(0);
 }

 if ("Cisco Telepresence Multipoint Switch" >< os)
 {
   v = eregmatch(string:os, pattern: "Product:Cisco Telepresence Multipoint Switch:([0-9.-]+)");
   if (isnull(v))
     os = "Cisco Telepresence Multipoint Switch";
   else
     os = "Cisco Telepresence Multipoint Switch " + v[1];
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if ("Cisco TelePresence MCU " >< os)
 {
   v = eregmatch(string:os, pattern: "Cisco TelePresence MCU ([0-9]+)");
   if (isnull(v))
     os = "Cisco Telepresence MCU ";
   else
     os = "Cisco Telepresence MCU " + v[1];
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if ("Digital UNIX" >< os )
 {
  version = ereg_replace(pattern:".*Digital UNIX V([0-9]\.[0-9]).*",
			 string:egrep(pattern:"Digital UNIX", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "Digital Unix " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }

 if ("ULTRIX" >< os )
 {
  version = ereg_replace(pattern:".*ULTRIX V([^ ]*).*",
			 string:egrep(pattern:"ULTRIX", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "ULTRIX " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }
 if ("HP-UX" >< os )
 {
   version = ereg_replace(pattern:".*HP-UX [^ ]* ([^ ]*) .*",
			  replace:"\1",
			  string:egrep(pattern:"HP-UX", string:os)
			 );
   if ( version != os )
   {
   set_kb_item(name:"Host/OS/SNMP", value:"HP-UX " + version);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
   }
 }

 # HP3000 SERIES e3000/A500-100-14, MPE XL version C.70.02 NS Transport version B.07.00
 if ("HP3000 " >< os && " MPE " >< os)
 {
   v = eregmatch(string: os, pattern: "HP3000 .* MPE (iX|XL version [^ ]+) ");
   if (! isnull(v))
   {
     set_kb_item(name:"Host/OS/SNMP", value:"HP 3000 - MPE/" + v[1]);
     set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
     set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   }
   else
   {
     set_kb_item(name:"Host/OS/SNMP", value:"HP 3000 - MPE/XL\nHP 3000 - MPE/iX\n");
     set_kb_item(name:"Host/OS/SNMP/Confidence", value: 75);
     set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   }
   exit(0);
 }

 if ( ereg(pattern:"^Brocade [0-9]+Gb SAN Switch Module for IBM eServer BladeCenter", string:os) )
 {
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if ( "IBM Infoprint " >< os )
 {
   os = "IBM Infoprint server " + ereg_replace(pattern:".*IBM Infoprint ([0-9]+).* [Vv]ersion ([0-9A-Z.]+).*", replace:"\1 Version \2", string:os);

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
 }

 if ("TGNet PSIO" >< os )
 {
  version = "TGNet Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ("JETDIRECT" >< os || "HP ETHERNET MULTI-ENVIRONMENT" >< os )
 {
  version = "HP JetDirect Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Lantronix UDS" >< os )
 {
  version = "Lantronix Universal Device Server";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Lantronix EPS1" >< os )
 {
  version = "Lantronix Ethernet Print Server";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if (ereg(pattern:"(^HP .*Switch|^PROCURVE |ProCurve .*Switch)", string:os))
 {
  version = "HP Switch";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if (os =~ "^IC109-FAST-KYO-TX" )
 {
  version = "KYOCERA Print Server";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if (os =~ "^KYOCERA.*Print" )
 {
  version = "KYOCERA Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "^OKI OkiLAN 8100e" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"EthernetBoard OkiLAN 8100e");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if (os =~ "XEROX.*Printer" || os =~ "XEROX DocuPrint" || "Xerox" >< os)
 {
  match = eregmatch(pattern:"((XEROX|Xerox|xerox)( DocuPrint( [A-Z0-9]+( |$|;))?|.*Printer))", string:os);
  if (!isnull(match))
    version = match[1];
  else
    version = "Xerox Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("NetQue" >< os )
 {
  report = "The remote host is running NetQue Printer Server";
  set_kb_item(name:"Host/OS/SNMP", value:"NetQue Printer Server");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 # http://www.dealtime.co.uk/xPF-Equinox_MDS_10_990410
 if ("EQUINOX MDS" >< os )
 {
  os = "Equinox MDS Transceiver";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Novell NetWare" >< os )
 {
  version = ereg_replace(pattern:".* NetWare ([^ ]*).*", string:os, replace:"\1");
  if (version != os)
  {
    # http://wiki.novell.com/index.php/Version_Decoder_Ring
    version = split(version, sep:'.', keep:0);
    for (i = 0; i < max_index(version); i++)
      version[i] = int(version[i]);
    for (i = max_index(version); i < 3; i++)
      version[i] = 0;

    os = "Novell NetWare";
    if (version[0] == 5)
    {
      if (version[1] == 70)
      {
        if (version[2] == 0) os += " 6.5 SP1";
        else os += " 6.5 SP" + version[2];
      }
      else if (version[1] == 60)
      {
        os += " 6.0 SP" + version[2];
      }
      else if (version[1] == 0)
      {
        if (version[2] == 11) os = 'Novell NetWare 5.1 SP8';
        else if (version[2] == 10) os = 'Novell NetWare 5.1 SP5\nNovell NetWare 5.1 SP7';
        else os = 'Novell NetWare 5.1';
      }
      else os = 'Novell NetWare';
    }
    else os = 'Novell NetWare';
  }
  else os = 'Novell NetWare';

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }


 if ("WorkCentre Pro Multifunction System" >< os )
 {
  os = "Xerox WorkCentre Pro";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( os =~ "SunOS .* 5\." )
 {
  snmp = os;

  ver = ereg_replace(pattern:"^SunOS .* 5\.([0-9]+) .*", string:os, replace:"\1");
  if (int(ver) >= 7) os = "Solaris " + ver;
  else os = "Solaris 2." + ver;

  if ( "i86pc" >< snmp ) os += " (i386)";
  else os += " (sparc)";


  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:99);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }

 if ( "Sun SNMP Agent" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Solaris");
  # Set the confidence to 5 because we can't distinguish the version of Solaris
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:5);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }

 if ( os =~ "^Microsoft Windows CE Version" )
 {
  version = ereg_replace(pattern:"^Microsoft Windows CE Version ([^ ]*).*", replace:"\1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:"Microsoft Windows CE Version " + version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);

 }
 if ( os == "Microsoft Corp. Windows 98.")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Microsoft Windows 98");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os =~  "Hardware:.*Software: Windows " )
 {
  os2 = ereg_replace(pattern:".*Software: Windows .*Version ([0-9.]+).*", string:os, replace:"\1");
  if ( os2 != os )
  {
   confidence = 75;
   if ( os2 == "4.0" )
    os = "Microsoft Windows NT 4.0";
   else if ( os2 == "5.0" )
    os = "Microsoft Windows 2000";
   else if ( os2 == "5.1" )
    os = "Microsoft Windows XP";
   else if (os2 == "5.2" )
    os = "Microsoft Windows Server 2003";
   else if (os2 == "6.0" )
   {
    os = 'Microsoft Windows Vista\nMicrosoft Windows Server 2008';
    confidence = 69;
   }
   else if (os2 == "6.1" )
   {
    os = 'Microsoft Windows 7\nMicrosoft Windows Server 2008 R2';
    confidence = 69;
   }
   else exit(0);

   #
   # Confidence level is 75 : pretty confident, but we do not have the Service Pack ID
   #
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }

 if ("AIX" >< os )
 {
  line = egrep(pattern:"AIX version", string:os);
  version = ereg_replace(pattern:".*AIX version ?: (.*)$", string:line, replace:"\1");
  if ( version != line )
  {
  version = split(version, sep:'.', keep:0);
  os = "AIX " + int(version[0]) + "." + int(version[1]);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }

 if (
  os == '"Videoconferencing Device"' ||
  os == "Videoconferencing Device" ||
  # nb: should contain embedded quotes???
  os == "Video Conferencing Device" ||
  os == "Videoconf Device"
 )
 {
   os = "Polycom Teleconferencing Device";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if (os == "NetPort Software 1.1")
 {
   os = "Polycom Teleconferencing Device";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 71);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if (os =~ "^Juniper Networks.*E320 Edge Routing Switch" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Juniper E320 Edge Routing Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ( "Juniper SR-" >< os || "Peribit SR-" >< os )
 {
  ver = ereg_replace(pattern:".*SR-([0-9]*).*", replace:"\1", string:os);
  os = "Juniper Peribit SR-" + ver;
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
  exit(0);
 }

 # NetEnforcerSGBS - Application Bandwidth Manager
 # AC - Application Bandwidth Manager
 if ( " - Application Bandwidth Manager" >< os  )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"NetEnforcer Application Bandwidth Manager");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
   exit(0);
 }

 if ( os =~ "Tru64 UNIX V[0-9.]+" )
 {
  version = ereg_replace(pattern:".*Tru64 UNIX V([0-9][0-9.]+([A-Z](-[0-9]+)?)?).*", replace:"\1", string:os);
  if ( version != os )
  {
   os = "Tru64 UNIX " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }

 if ("Enterasys Networks, Inc. Matrix" >< os)
 {
   v = eregmatch(string:os, pattern:" Matrix ([EN])[0-9]+ Platinum");
   os = "Enterasys Networks Matrix";
   if (!isnull(v)) os += strcat(" ", v[1], "-Series Platinum");

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if ( "NetApp Release " >< os )
 {
  v = eregmatch(string: os, pattern: " Release ([0-9][^ ]+)");
  if (! isnull(v))
  {
    os = "NetApp Release " + v[1];
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  }
  else
  {
    os = "NetApp";
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  }
  exit(0);
 }

 if ( "DSR2035 " >< os )
 {
  os = "DSR2035 KVM Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Darwin Kernel Release" >< os )
 {
   os = ereg_replace(string:os, pattern:".*Darwin Kernel Release Version ([0-9.]+).*", replace:"\1");
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ( "Darwin Kernel Version" >< os )
 {
   os = ereg_replace(string:os, pattern:".*Darwin Kernel Version ([0-9.]+).*", replace:"\1");
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/SNMP", value:version);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ( os =~ "^Linux " )
 {
  version = ereg_replace(pattern:"Linux [^ ]* (([2-9]|[1-9][0-9]+)\.[^ ]*).*", replace:"\1", string:os);
  if ( version != os )
  {
  version = "Linux Kernel " + version;
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }
 if ( "kernel 2." >< os )
 {
  version = ereg_replace(pattern:".* kernel (2\.[0-9])\..*", replace:"\1", string:os);
  if ( version != os )
  {
  version = "Linux Kernel " + version;
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }

 if ("Modbus/TCP to RTU Bridge" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Modbus/TCP to RTU Bridge");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"scada");
  exit(0);
 }
 if ("NetBotz RackBotz 400 Appliance" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"NetBotz RackBotz 400 Appliance");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if (
   os =~ "Fibre Channel Switch" ||
   os =~ "^Brocade Communications Systems, Inc. FE"
 )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Brocade Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if (ereg(pattern:"^V-M200 - Hardware revision", string:os))
 {
  match = eregmatch(pattern:"^V-([^ ]+) - Hardware revision .+ Firmware version ([0-9][^ ]+)", string:os);
  if (isnull(match)) os_name = "HP Access Point";
  else os_name = "HP " +match[1] + " Access Point with Firmware version " + match[2];

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if  ("ProCurve Access Point" >< os )
 {
  os = ereg_replace(pattern:"ProCurve Access Point ([^ ]*).*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:"HP Access Point " + os );
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ("NCD ThinSTAR " >< os )
 {
  os = ereg_replace(pattern:"NCD ThinSTAR [^ ]*.*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:"NCD ThinSTAR " + os );
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose"); # embedded?
  exit(0);
 }
 if ( "Fluke Networks OptiView (tm) Integrated Network Analyzer" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Fluke Optiview Network Analyzer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if (os =~ "Canon iR ?[A-Z0-9]+" )
 {
  model = ereg_replace(pattern:".*Canon iR ?([^ ]*).*$", string:os, replace:"\1");
  if ( model != os )
   set_kb_item(name:"Host/OS/SNMP", value:"Canon imageRUNNER " + chomp(model) + " Printer");
  else
   set_kb_item(name:"Host/OS/SNMP", value:"Canon imageRUNNER Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("Canon LBP" >< os )
 {
   num = ereg_replace(string:os, pattern:"^Canon LBP([0-9]+) .*", replace:"\1");
   if ( num == os ) num = "";
  set_kb_item(name:"Host/OS/SNMP", value:"Canon LBP" + num + " Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("Canon Network Multi-PDL Printer Board" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Canon Network Multi-PDL Printer Board");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if (os =~ "^MF series printer" || os =~ "^Canon MF[0-9][^ ]+ Series")
 {
   match = eregmatch(pattern:"^Canon (MF[0-9][^ ]+) Series", string:os);
   if (isnull(match)) os_name = "Canon MF Series Printer";
   else os_name = "Canon " + match[1] + " Series Printer";

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( "Alcatel SPEEDTOUCH" >< os || os =~ "^SpeedTouch" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Alcatel SpeedTouch DSL Modem");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "Digi International PortServer" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Digi International PortServer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "^BEFSX" )
 {
  os = "Linksys BEFSX Router";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^Passport-[0-9]"  )
 {
  os = "Nortel Passport Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "^Netopia [0-9]*.* v[0-9.]*[A-Z0-9.]*")
 {
  os = ereg_replace(pattern:"^Netopia ([^ ]*).*", replace:"Netopia \1 Router", string:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^KONICA MINOLTA" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Konica Minolta Digital Copier/Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if (os =~ "^Minolta Di[0-9]+$")
 {
  set_kb_item(name:"Host/OS/SNMP", value: os + " Digital Copier/Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value: "printer");
  exit(0);
 }

 if ( os =~ "^EPSON.*Print Server" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"EPSON Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "Brother NC-.*Firmware")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Brother Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if (os =~ "SHARP (AR|MX)-[^ ]+$")
 {
  match = eregmatch(pattern:"SHARP ((AR|MX)-[^ ]+)$", string:os);
  if (isnull(match)) os = "Sharp Printer";
  else os = "Sharp " + match[1] + " Printer";

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:80);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "ALCATEL VoIP terminal" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Alcatel VoIP terminal");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "^Cayman-DSL" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Cayman DSL Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }

 if ("ADSL Router, VxWorks SNMPv1/v2c Agent, Conexant System, Inc. " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Conexant ADSL Modem");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "3COM VCX Server" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"3com VCX VoIP Server");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Packeteer PacketShaper " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Packeteer PacketShaper");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
  exit(0);
 }

 if ( "Lucent Technologies Cajun Switch Agent " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Lucent Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ( "APC Environmental Monitoring Unit" >< os )
 {
  #http://www.apc.com/products/family/index.cfm?id=47
  set_kb_item(name:"Host/OS/SNMP", value:"APC Environmental Monitoring Unit");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("VMware ESX" >< os && "VMware, Inc." >< os)
 {
  match = eregmatch(pattern:"VMware ESX ([0-9.]+ build-[0-9]+)", string:os);
  os = "VMware ESX";
  if (match) os += " " + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"hypervisor");
  exit(0);
 }

 if ( "DynaStar 500" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"DynaStar 500");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Muratec F-" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Muratec Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "ZebraNet PrintServer" >< os ||
      "ZebraNet Wired PS" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"ZebraNet Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Xserve RAID" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Xserve RAID");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ("Cisco Systems Catalyst 1900" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"CatalystOS 1900");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ '^"?m0n0wall' )
 {
  v = ereg_replace(pattern:'^"?m0n0wall [^ ]* ([0-9.]+) .*', replace:"\1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:"m0n0wall " + v + " Firewall");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
  exit(0);
 }
 if ( os =~ "^Blue Coat SG.*Version:" )
 {
   v = ereg_replace(pattern:"^Blue Coat (SG[^ ]*) Series,.*", replace:"\1", string:os);
   set_kb_item(name:"Host/OS/SNMP", value:"Blue Coat " + v);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if ("Generic 28C-1" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:70);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("Cyber Switching ePower(tm) PDU" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Cyber Switching ePower PDU");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ( "Dell 1815dn Series" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Dell Laser Printer 1815dn Series");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ("SonicWALL " >< os && "(SonicOS " >< os && ereg(pattern:"^SonicWALL (.+) \(SonicOS ([^)]+)\)", string:os))
 {
   match = eregmatch(pattern:"^SonicWALL (.+) \(SonicOS ([^)]+)\)", string:os);
   os = "SonicOS " + match[2] + " on a SonicWALL " + match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
   exit(0);
 }
 if ( "vSphere Management Assistant " >< os )
 {
  v = ereg_replace(pattern:'^["]*vSphere Management Assistant ([0-9.]+).*', replace:"\1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:"VMware vSphere Management Assistant " + v);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }
 if ( "SR-140. H/W: SHDSL" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"AirTies SR-140 SHDSL Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^Juniper Networks" && "internet router" >< os)
 {
  match = eregmatch(string:os, pattern:"JUNOS ([0-9]+\.[0-9]+[A-Z][0-9.]+)");
  if (match)
  {
    set_kb_item(name:"Host/OS/SNMP", value:"Juniper Router Junos Version " + match[1]);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
    exit(0);
  }
 }
 if ( "Barracuda SSL VPN" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Barracuda SSL VPN");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"VPN");
  exit(0);
 }

 if ( "Barracuda Web Application Firewall" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Barracuda Web Application Firewall");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ( "SONY Network Camera SNC-" >< os)
 {
  match = eregmatch(string:os, pattern:"SONY Network Camera SNC-([A-Z0-9]+)");
  if (match)
  {
    set_kb_item(name:"Host/OS/SNMP", value:"SONY Network Camera SNC-" + match[1]);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"camera");
    exit(0);
  }
 }

 if ( "ExtremeXOS version " >< os)
 {
  match = eregmatch(string:os, pattern:"ExtremeXOS version ([0-9].+)");
  if (match)
  {
    os = "ExtremeXOS Network Operating System " + match[1];
    os = os - strstr(os, " by release-manager");
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
    exit(0);
  }
 }
 # eg, "IPSO hostname 3.8.1-BUILD028 releng 1518  12.02.2004-222502 i386"
 if ( os =~ "^IPSO [^ ]+ " && "-BUILD" >< os)
 {
  match = eregmatch(string:os, pattern:"IPSO [^ ]+ ([0-9][0-9.]+-BUILD.+)");
  if (match)
  {
    os = "Nokia IPSO Firewall " + match[1];
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
    exit(0);
  }
 }
 if ( os =~ "^D-Link DP" && " Print Server" >< os )
 {
  match = eregmatch(string:os, pattern:"^D-Link (DP[^ ]+) Print Server");
  if (match)
  {
    os = "D-Link Print Server - " + match[1];
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"printserver");
    exit(0);
  }
 }
 if ( ereg(pattern:"^AX[0-9]+SCi? - Flare", string:os) )
 {
  match = eregmatch(pattern:"^(AX[0-9]+SCi?) - Flare ([0-9][0-9.]+)", string:os);
  if (match)
  {
    os = "EMC CLARiiON " + match[1] + " SAN Disk Array with Flare " + match[2];
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
    exit(0);
  }
 }
 # APC Web/SNMP Management Card
 if ( os =~ "^APC Web/SNMP Management Card" )
 {
  match = eregmatch(pattern:"^APC Web/SNMP Management Card .+ MN:(AP[0-9]{4}[A-Z]*)", string:os);
  if (match)
  {
    os = "APC " + match[1] + " UPS Network Management Card";
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
    exit(0);
  }
 }
 if ("SecureOS " >< os)
 {
  match = eregmatch(string:os, pattern:"SecureOS [^ ]+ ([0-9][0-9.]+) SW_OPS");
  if (match)
  {
    os = "SecureOS " + match[1];
    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
    exit(0);
  }
 }

 if (
   "TANDBERG Video Communication Server" >< os ||
   "TANDBERG Codec" >< os ||
   "Cisco Codec" >< os
 )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Cisco Video Communication Server");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if (os == "Avaya Phone")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Avaya IP Phone");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("TTN_CORP Version: " >< os)
 {
  # nb: this is a customized version of GuardianOS from Total Training Networks.
  match = eregmatch(pattern:"^TTN_CORP Version: ([0-9.]+)", string:os);
  os = "GuardianOS";
  if (match) os += " " + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Product: EMC Celerra File Server " >< os)
 {
  match = eregmatch(pattern:"Version: +T([0-9.]+)", string:os);
  os = "EMC Celerra File Server";
  if (match) os += " with DART T" + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Janitza electronics" >< os)
 {
  match = eregmatch(pattern:"Janitza electronics UMG([0-9.]+)", string:os);
  os = "Janitza electronics";
  if (match) os += " " + match[1];

  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if (
   "Cisco Nexus Operating System (NX-OS) Software" >< os ||
   "Cisco NX-OS" >< os
 )
 {
  if (ver = eregmatch(string:os, pattern:", Version ([^,]+),"))
    os_name = "Cisco NX-OS Version " + ver[1];
  else
    os_name = "Cisco NX-OS";

  set_kb_item(name:"Host/OS/SNMP", value:os_name);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ("Cisco ONS" >< os)
 {
   set_kb_item(name:"Host/OS/SNMP", value:"Cisco ONS");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if ("AirCam" >< os)
 {
   set_kb_item(name:"Host/OS/SNMP", value:"Ubiquiti airCam");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if (";VerPl:3300 ICP" >< os && "VerAg:" >< os)
 {
   set_kb_item(name:"Host/OS/SNMP", value:"Mitel IP Communications Platform");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"pbx");
 }

 if (ereg(pattern:"Product: MG ([0-9]+);SW Version: ([0-9][0-9A-Z.]+)", string:os))
 {
   match = eregmatch(pattern:"Product: MG ([0-9]+);SW Version: ([0-9][0-9A-Z.]+)", string:os);
   os = "Mediant " + match[1] + " Media Gateway with firmware " + match[2];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if (ereg(pattern:"AXIS ([0-9][^ ]+) Network Document Server", string:os))
 {
   match = eregmatch(pattern:"AXIS ([0-9][^ ]+) Network Document Server(,Version: ([0-9][^ ]+))?", string:os);
   os = "AXIS " + match[1] + " Network Document Server";
   if (match[3]) os += " with firmware " + match[3];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");  # 'scanner'?
 }

 if (ereg(pattern:"AXIS ([0-9][^ ]+) Network Print Server", string:os))
 {
   match = eregmatch(pattern:"AXIS ([0-9][^ ]+) Network Print Server( V([0-9][^ ]+))?", string:os);
   os = "AXIS " + match[1] + " Network Print Server";
   if (match[3]) os += " with firmware " + match[3];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");  # 'scanner'?
 }

 if (ereg(pattern:"^Palo Alto Networks ([^ ]+) series firewall", string:os))
 {
   match = eregmatch(pattern:"^Palo Alto Networks ([^ ]+) series firewall", string:os);
   os = "Palo Alto Networks PAN-OS on a " + match[1] + " series firewall";

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
 }

 if (ereg(pattern:"^MPU([0-9]+E?) ([0-9]+(\.[0-9]+)+)$", string:os))
 {
   match = eregmatch(pattern:"^MPU([0-9]+E?) ([0-9]+(\.[0-9]+)+)$", string:os);
   os = "Avocent MergePoint Unity " + match[1] + " KVM switch with firmware version " + match[2];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
 }

 if (ereg(pattern:"^Mediatrix ([0-9][0-9-]+)( plus)? v?([0-9]+(\.[0-9]+)+) ", string:os))
 {
   match = eregmatch(pattern:"^Mediatrix ([0-9][0-9-]+)( plus)? v?([0-9]+(\.[0-9]+)+) ", string:os);
   if (match[1] =~ "^41") os = "Mediatrix " + match[1] + " VoIP Adapter with firmware version " + match[3];
   else if (match[1] =~ "^(3|44)") os = "Mediatrix " + match[1] + " VoIP Gateway with firmware version " + match[3];
   else os = "Mediatrix " + match[1] + " VoIP Gateway with firmware version " + match[3];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if (ereg(pattern:"NetScaler NS([0-9.]+):[ \t]+Build ([0-9][^ \t,]+), Date", string:os))
 {
   match = eregmatch(pattern:"NetScaler NS([0-9.]+):[ \t]+Build ([0-9][^ \t,]+), Date", string:os);
   os = "Citrix NetScaler " + match[1] + " Build " + match[2];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }

 if (ereg(pattern:"VBrick Systems Inc\., Model (.+) Serial ", string:os))
 {
   match = eregmatch(pattern:"VBrick Systems Inc\., Model (.+) Serial ", string:os);
   os = "VBrick " + match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
 }
 if ("IBM Networking Operating System RackSwitch" >< os )
 {
   match = eregmatch(pattern:"IBM Networking Operating System RackSwitch ([A-Z][0-9]+)$", string:os);
   os = "IBM BNT";
   if (!isnull(match)) os += " " + match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }
 if (os =~ "Hardware:.* Software: FBLOS")
 {
   match = eregmatch(pattern:"Hardware: (Forti[^ ]+ [0-9][^ ]+) .+Software: FBLOS Rel\.FBL\.([0-9]+(\.[0-9]+)+)", string:os);
   os = "FBLOS";
   if (!isnull(match)) os += " " + match[2] + " on a Fortinet " + match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"load-balancer");
   exit(0);
 }

  if (ereg(pattern:"^AX Series .*[ (]ACOS[ )]", string:os))
  {
    match= eregmatch(pattern:"^AX Series .*[ (]ACOS[ )](.* )?([\-0-9.pPgGrR]+),[ \t\n]*$", string:os);

    os = "A10 Networks Advanced Core OS";
    if (!isnull(match)) os += ' ' + match[2];

    set_kb_item(name:"Host/OS/SNMP", value:os);
    set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
    set_kb_item(name:"Host/OS/SNMP/Type", value:"load-balancer");
    exit(0);
  }

 if ("Compaq Windows-based Terminal" >< os )
 {
   match = eregmatch(pattern:"^Compaq Windows-based Terminal Version ([0-9.]+) SP ([0-9]+)", string:os);

   os = "Compaq Windows-based Terminal";
   if (!isnull(match)) os += " Version "+ match[1] +" SP "+ match[2];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if ("ConnectUPS Web/SNMP Card" >< os )
 {
   # nb: these devices are commonly but not exclusively
   #     associated with Eaton Powerware UPSes.
   match = eregmatch(pattern:"^ConnectUPS Web/SNMP Card V([0-9.]+)", string:os);

   os = "ConnectUPS Web/SNMP Card";
   if (!isnull(match)) os += " "+ match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if ("running IRIX " >< os )
 {
   # nb: these devices are commonly but not exclusively
   #     associated with Eaton Powerware UPSes.
   match = eregmatch(pattern:"^Silicon Graphics .+ running IRIX ([0-9]+(\.[0-9]+)+[a-z]?)", string:os);

   os = "IRIX";
   if (!isnull(match)) os += " "+ match[1];

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 match = eregmatch(pattern:"^GCM(16|32) ([0-9]+(\.[0-9]+)+)$", string:os);
 if (!isnull(match))
 {
  os = "IBM Global Console Manager GCM"+ match[1] + " KVM with firmware " + match[2];
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");  # 'kvm'?
  exit(0);
 }

 if ("VxWorks" >< os ) # Must be last
 {
  set_kb_item(name:"Host/OS/SNMP", value:"VxWorks");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ("Silver Peak Systems" >< os)
 {
  #Silver Peak Systems, Inc. VXUNLICENSED
  #Linux silverpeak 2.6.38.6-rc1 #1 VXOA 6.2.4.0_49732 SMP Tue
  #Apr 1 22:58:40 PDT 2014 x86_64

   os_value = "Silver Peak Systems";
   match = eregmatch(pattern:"(Linux silverpeak [0-9\.A-Za-z\-]+)", string:os);
   if (!isnull(match))
   {
     os_value = os_value + " " + match[1];
   }
   set_kb_item(name:"Host/OS/SNMP", value:os_value);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ( os =~ "^Thermal Label Printer Intermec" )
 {
  os = "Intermec Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Meinberg LANTIME" >< os || "lantime" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Meinberg LANTIME");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"scada");
  exit(0);
 }
 if ( "Troy XJet" >< os )
 {
   match = eregmatch(pattern:"(Troy XJet ?[0-9]+)", string:os);
   if (!isnull(match))
     os_value = match[1];
   else os_value = os;
   set_kb_item(name:"Host/OS/SNMP", value:os_value);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:80);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("Arista Networks EOS version" >< os && "running on an Arista Networks" >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Arista EOS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 99);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
}
