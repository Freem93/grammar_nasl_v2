#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25251);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/07/08 20:33:51 $");

  script_name(english:"OS Identification : Unix uname");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
response returned by 'uname -a'.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and version
by looking at the data returned by 'uname -a'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);

confidence = 100;
type = "general-purpose";

set_kb_item(name:"Host/OS/uname/Fingerprint", value:uname);
array = eregmatch(pattern:"^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*).*", string:uname);
if ( isnull(array) ) exit(0);

if ( array[1] == "Linux" )
{
  kb = get_kb_item("Host/etc/redhat-release");

  match = eregmatch(pattern:"^(.+)\.([^.]*LEAF)$", string:array[3]);
  if ('-LEAF' >< array[3] && !isnull(match))
  {
   os = "Linux Kernel " + match[1] + ' on ' + match[2];
   type = "embedded";
  }
  else if (array[3] =~ "\.amzn[0-9]+\.")
  {
    os = "Amazon Linux AMI";
    kb = get_kb_item("Host/AmazonLinux/release");
    if (!isnull(kb) && os >< kb)
    {
      match = eregmatch(pattern:"^ALA([0-9]+\.[0-9.]+)", string:kb);
      if (!isnull(match)) os += " " + match[1];
    }

    kernel = ereg_replace(pattern:"\.amzn[0-9]+\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "\.mlos[0-9]+\.mwg")
  {
    os = "McAfee Linux OS";
    if (!isnull(kb) && os >< kb)
    {
      match = eregmatch(pattern:"^McAfee Linux OS release ([0-9]+\.[0-9.]+)", string:kb);
      if (!isnull(match)) os += " " + match[1];
    }

    kernel = ereg_replace(pattern:"\.mlos[0-9]+\.mwg\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (array[3] =~ "uek$" && !isnull(kb) && "Oracle VM server" >< kb)
  {
    os = "Oracle VM Server";
    match = eregmatch(pattern:"^Oracle VM server release ([0-9]+\.[0-9.]+)", string:kb);
    if (!isnull(match)) os += " " + match[1];

    kernel = ereg_replace(pattern:"\.mlos[0-9]+\.mwg\..+$", replace:"", string:array[3]);
    if (kernel =~ "^[0-9]+\.[0-9.-]+$") os = "Linux Kernel " + array[3] + " on " + os;
  }
  else if (!isnull(kb) && "PelcoLinux" >< kb)
  {
    os = "PelcoLinux";
    match = eregmatch(pattern:"^PelcoLinux release ([0-9]+[0-9.]*)", string:kb);
    if (!isnull(match)) os += " release " + match[1];

    os = "Linux Kernel " + array[3] + " on " + os;
  }
  else
  {
   kb = get_kb_item("Host/etc/Eos-release");
   if(!isnull(kb) && "Arista Networks EOS" >< kb)
   {
     ver = get_kb_item("Host/Arista-EOS/Version");
     if(isnull(ver)) ver = '';
     os = "Arista EOS " + ver;

     os = "Linux Kernel " + array[3] + " on " + os;

     type = "switch";
   }
   else
   {
     os = "Linux Kernel " + array[3];
     confidence --; # we don't have the distribution
   }
  }
 }


else if ( array[1] == "Darwin" )
{
 os = get_kb_item("Host/MacOSX/Version");
 if (isnull(os))
 {
  num = split(array[3], sep:".", keep:FALSE);
  os = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
 }
}
else if ( array[1] == "SecureOS" )
{
 os = get_kb_item("Host/SecureOS/release");
 if (isnull(os)) os = array[1] + " " + array[3];
 type = "firewall";
}
else if ( array[1] == "FreeBSD" )
{
 os = get_kb_item("Host/FreeBSD/release");
 if (!isnull(os) && "FreeBSD-" >< os)
 {
  os = str_replace(find:"FreeBSD-", replace:"FreeBSD ", string:os);
 }
 else os = array[1] + " " + array[3];
}
else if ( array[1] == "NetBSD" )
{
  os = "NetBSD";
  match = eregmatch(pattern:"^NetBSD .+ NetBSD ([0-9]+[0-9.]+) .+ ([^ ]+)$", string:uname);
  if (!isnull(match)) os += " " + match[1] + " (" + chomp(match[2]) + ")";
}
else if (array[1] == "OpenBSD")
{
  os = get_kb_item("Host/OpenBSD/release");
  if (!isnull(os) && "OpenBSD-" >< os)
  {
    os = str_replace(find:"OpenBSD-", replace:"OpenBSD ", string:os);
  }
  else os = array[1] + " " + array[3];
}
else if ( array[1] == "SunOS" )
{
 num = split(array[3], sep:".", keep:FALSE);
 if (int(num[1]) >= 7) os = "Solaris " + num[1];
 else os = "Solaris 2." + num[1];
 if ( "sparc" >< uname ) os += " (sparc)";
 else if ( "i386" >< uname ) os += " (i386)";
}
else if ( array[1] == "AIX" )
{
  # AIX servername 3 5 000B8AC4D600
  os = strcat("AIX ", array[4], ".", array[3]);

  oslevel = get_kb_item("Host/AIX/oslevel");
  if (oslevel)
  {
    match = eregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])$", string:oslevel);
    if (!isnull(match)) os += " TL " + int(match[2]);
  }

  oslevelsp = get_kb_item("Host/AIX/oslevelsp");
  if (oslevelsp)
  {
    match = eregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])-([0-9][0-9][0-9][0-9])$", string:oslevelsp);
    if (!isnull(match)) 
    {
      if (" TL " >!< os) os += " TL " + int(match[2]);
      os += " SP " + int(match[3]);
    }
  }
}
else if ( array[1] =~ "^(CYGWIN|MINGW32)" )
{
 os = 'Microsoft Windows';
 confidence = 30;
}
else if (array[1] == "JUNOS" )
{
 os = strcat("Juniper Junos Version ", array[3]);
}
else if (array[1] == "Haiku" )
{
 os = strcat("Haiku OS");
}
else if ( array[1] !~ "Linux|BSD|HP-UX|AIX|SunOS|Darwin|Minix|SCO_SV|IRIX|DragonFly|Haiku" )
{
  os = array[1] + " " + array[3]; confidence -= 35; # Unknown OS or error when executing uname?
}
else { os = array[1] + " " + array[3]; confidence -= 10; }


set_kb_item(name:"Host/OS/uname", value:os);
set_kb_item(name:"Host/OS/uname/Confidence", value:confidence);
set_kb_item(name:"Host/OS/uname/Type", value:type);

