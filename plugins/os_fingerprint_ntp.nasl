#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25244);
  script_version("$Revision: 1.51 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : NTP");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
data returned by the NTP server.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system type and version
by looking at the NTP data returned by the remote server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("Host/OS/ntp");

  exit(0);
}

#
# If NTP is open, try to read data from there. We have to
# normalize the data we get, which is why we don't simply
# spit out 'Host/OS/ntp'
#
os = get_kb_item("Host/OS/ntp");
if ( os )
{
 set_kb_item(name:"Host/OS/NTP/Fingerprint", value:os);
 processor = get_kb_item("Host/processor/ntp");
 # Normalize intel CPUs
 if ( processor && ereg(pattern:"i[3-9]86", string:processor)) processor = "i386";

 if ("QNX" >< os )
 {
  version = str_replace(find:"QNX", replace:"QNX ", string:os);
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
  set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
  exit(0);
 }
 if ("sparcv9-wrs-vxworks" >< os )
 {
   version = "VxWorks";
   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:50);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }
 if ( "Darwin" >< os && "Power Macintosh" >< processor )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("OpenVMS AXP" >< os || "OpenVMS/V" >< os)
 {
   set_kb_item(name:"Host/OS/NTP", value: "OpenVMS");
   set_kb_item(name:"Host/OS/NTP/Confidence", value: 80);
   set_kb_item(name:"Host/OS/NTP/Type", value: "general-purpose");
   exit(0);
 }

 if ( "Darwin" >< os && ("i386" >< processor || "x86_64" >< processor) )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   if ( int(num[0]) == 8 && int(num[1]) == 8 && int(num[2]) == 2 )
   {
    version = "AppleTV/3.0";
    set_kb_item(name:"Host/OS/NTP", value:version);
    set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
    set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   }
   else
   {
    version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1] + " (intel)";
    set_kb_item(name:"Host/OS/NTP", value:version);
    set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
    set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   }
   exit(0);
 }

 if ("UNIX/HPUX" >< os )
 {
   set_kb_item(name:"Host/OS/NTP", value:"HP-UX");
   set_kb_item(name:"Host/OS/NTP/Confidence", value:50);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("HP-UX/" >< os )
 {
  set_kb_item(name:"Host/OS/NTP", value:"HP-UX");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:80);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }

 if ("NetBSD" >< os )
 {
   if ("NetBSD/" >< os) os -= "NetBSD/";
   else os -= "NetBSD";
   version = "NetBSD " + os;
   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("FreeBSD" >< os && "-NETSCALER-" >!< os)
 {
   os -= "FreeBSD";
   if ( os =~ "^/" ) os -= "/";
   version = "FreeBSD " + os;

   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("WINDOWS/NT" >< os || os == "Windows" )
 {
   os = "Microsoft Windows";
   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:10);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("OpenBSD" >< os )
 {
   os -= "OpenBSD";
   version = "OpenBSD" + os;
   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if (ereg(pattern:"^Linux/.+-nam$", string:os))
 {
   set_kb_item(name:"Host/OS/NTP", value:"CISCO Network Analysis Module (NAM)");
   set_kb_item(name:"Host/OS/NTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if (ereg(pattern:"^Linux/.+\.[^.]*LEAF$", string:os))
 {
   match = eregmatch(pattern:"^Linux/(.+)\.([^.]*LEAF)$", string:os);
   os = "Linux Kernel " + match[1] + ' on ' + match[2];
   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if (ereg(pattern:"^Linux/.+\.amzn[0-9]+\.", string:os))
 {
   match = eregmatch(pattern:"^Linux/(.+)\.amzn[0-9]+\.", string:os);
   os = "Linux Kernel " + match[1] + ' on Amazon Linux AMI';
   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if (ereg(pattern:"^Linux/(\d+\.\d+).*\.vz(\d+)\.([0-9.]+)", string:os))
 {
   conf = 90;
   matches = eregmatch(
     pattern:"^Linux/(\d+\.\d+).*\.vz(\d+)\.([0-9.]+)",
     string:os
   );

   if (matches[3] == "20.18")
     os = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release 7.3';
   else if (matches[3] == "15.2")
     os = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release 7.2';
   else
   {
     os = 'Linux Kernel ' + matches[1] + ' on Virtuozzo release ' + matches[2];
     conf = 70;
   }

   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:conf);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 # This needs to be before the if ("Linux" >< os) block since it can look like "Linux2.6.11LantronixSLC"
 if ("LantronixSLC" >< os )
 {
   set_kb_item(name:"Host/OS/NTP", value:"Lantronix SLC");
   set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if ("Linux" >< os )
 {
   confidence = 75;
   if ("Linux/" >< os ) os -= "Linux/";
   else os -= "Linux";
   os = "Linux Kernel " + os;
   version = os;
   if ( version =~ "Linux Kernel [0-9]\.[0-9]\.[0-9]" )
	confidence = 95;

   match = eregmatch(pattern:"\.mga(\d*)$", string:os);
   if (!isnull(match))
   {
     if (strlen(match[1]) == 0) version += " on Mageia 1";
     else version += " on Mageia " + match[1];
   }

   if ( processor )
   {
     version += " (" + processor + ")";

     # nb: reduce confidence for Linux on ARM so other
     #     fingerprints take precedence.
     if ("armv" >< processor) confidence -= 15;
   }

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ( "cisco" >< os )
 {
  set_kb_item(name:"Host/OS/NTP", value:"CISCO IOS");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:6);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ("SunOS5." >< os )
 {
  os -= "SunOS5.";
  if (int(os) >= 7) os = "Solaris " + os;
  else os = "Solaris 2." + os;
  version = os;
  if ( processor ) version += " (" + processor + ")";
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 else if ("SunOS/5." >< os )
 {
  os -= "SunOS/5.";
  if (int(os) >= 7) os = "Solaris " + os;
  else os = "Solaris 2." + os;
  version = os;
  if ( processor ) version += " (" + processor + ")";
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 else if ( os == "SunOS" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"Solaris");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( "UNIX/AIX" >< os )
 {
  set_kb_item(name:"Host/OS/NTP", value:"AIX");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os == "cisco" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"CISCO IOS");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:10);
  set_kb_item(name:"Host/OS/NTP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^OSF1V[0-9.]*$" )
 {
  os -= "OSF1V";
  set_kb_item(name:"Host/OS/NTP", value:"Tru64 UNIX " + os);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os == "SCO_SV" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"SCO OpenServer");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( ver = eregmatch(string:os, pattern:"^JUNOS([0-9]+\.[0-9]+[A-Z][A-Z0-9.-]+)$") )
 {
  # 'os' looks like "JUNOS10.2R3.10"
  #         or like "JUNOS12.1X44-D10.4"
  set_kb_item(name:"Host/OS/NTP", value:"Juniper Junos Version " + ver[1]);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
  set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
  exit(0);
 }

 if ( os == "IPSO" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"Nokia IPSO Firewall");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"firewall");
  exit(0);
 }

 v = eregmatch(string: os, pattern: "^VMkernel/([0-9][0-9.]+)$");
 if (! isnull(v))
 {
  set_kb_item(name:"Host/OS/NTP", value: "VMware ESX "+v[1]);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
  set_kb_item(name:"Host/OS/NTP/Type", value:"hypervisor");
  exit(0);
 }

 if ("-NETSCALER-" >< os )
 {
   v = eregmatch(string:os, pattern:"-NETSCALER-([0-9][0-9.]+)");
   os = "Citrix NetScaler";
   if (!isnull(v)) os += " " + v[1];

   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if ("SecureOS/" >< os )
 {
   v = eregmatch(string:os, pattern:"SecureOS/([0-9][0-9.]+)");
   os = "SecureOS";
   if (!isnull(v)) os += " " + v[1];

   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"firewall");
   exit(0);
 }

 if ("Isilon OneFS" >< os )
 {
   v = eregmatch(string:os, pattern:"Isilon OneFS/v([0-9][0-9.]+)");
   os = "Isilon OneFS";
   if (!isnull(v)) os += " v" + v[1];

   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

 if ("Data ONTAP" >< os )
 {
   v = eregmatch(string:os, pattern:"Data ONTAP/([0-9]+\.[0-9][^ ]+)");
   os = "NetApp";
   if (!isnull(v)) os += " Release " + v[1];

   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }

}
