#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35658);
  script_version("$Revision: 1.57 $");
  script_cvs_date("$Date: 2017/01/19 04:19:04 $");

  script_name(english:"OS Identification : FTP");
  script_summary(english:"Determines the remote operating system from the FTP banner.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on the
FTP banner.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system based on the
response from the remote host's FTP banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

function test(banner)
{
  local_var conf, match, os, version;

# 220 X.Y.COM MultiNet FTP Server Process V4.4(16) at Thu 20-Nov-2008 8:24AM-PST
if ("MultiNet FTP Server Process" >< banner)
{
 set_kb_item(name:"Host/OS/FTP", value:"OpenVMS");
 set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
 exit(0);
}

# 220 P-660RU-T FTP version 1.0 ready at Sat Feb 05 19:17:46 2000
if ("P-660RU-T FTP version " >< banner)
{
 set_kb_item(name:"Host/OS/FTP", value:"ZyXEL Prestige 660RU-T ADSL Router");
 set_kb_item(name:"Host/OS/FTP/Type", value:"router");
 set_kb_item(name:"Host/OS/FTP/Confidence", value: 76);
 exit(0);
}

if (egrep(string: banner, pattern: "FTP server \(Version [0-9]+\(PHNE_[0-9]+\) "))
{
  set_kb_item(name:"Host/OS/FTP", value:"HP-UX");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
  exit(0);
}

if (" Microsoft FTP Service (Version 4.0)." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: "Microsoft Windows NT 4.0");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 60);
  exit(0);
}


if (" Microsoft FTP Service (Version 5.0)." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: "Microsoft Windows 2000");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 60);
  exit(0);
}

if ("Microsoft FTP Service" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Microsoft Windows Server 2003");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
  exit(0);
}

if (" FTP server (Version 6.4/OpenBSD) ready." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 2.6\nOpenBSD 2.7');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (Version 6.5/OpenBSD) ready." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 2.8\nOpenBSD 2.9\nOpenBSD 3.0\nOpenBSD 3.1\nOpenBSD 3.2\nOpenBSD 3.3\nOpenBSD 3.4\nOpenBSD 3.5\nOpenBSD 3.6');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (Version 6.6/OpenBSD) ready." >< banner)
{
# OpenBSD 4.2 or 4.3 say: FTP server ready.
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 3.7\nOpenBSD 3.8\nOpenBSD 3.9\nOpenBSD 4.0\nOpenBSD 4.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (NetBSD-ftpd 20050303) " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'NetBSD 3.0.2\nNetBSD 3.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (NetBSD-ftpd 20060923nb4) " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'NetBSD 4.0.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 65);
  exit(0);
}
if (" FTP server (NetBSD-ftpd 20100320) " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:'NetBSD 5.1.3\nNetBSD 5.1.4\nNetBSD 5.1.5\nNetBSD 5.2.1\nNetBSD 5.2.2\nNetBSD 5.2.3\nNetBSD 6.0\nNetBSD 6.0.1\nNetBSD 6.0.2\nNetBSD 6.0.3\nNetBSD 6.0.4\nNetBSD 6.0.5\nNetBSD 6.0.6\nNetBSD 6.1\nNetBSD 6.1.2\nNetBSD 6.1.3\nNetBSD 6.1.4\nNetBSD 6.1.5');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:55);
  exit(0);
}
if (" FTP server (SunOS" >< banner)
{
  os = "Solaris";
  match = eregmatch(pattern:" FTP server \(SunOS 5\.([0-9]+)", string:banner);
  if (!isnull(match))
  {
    version = match[1];
    if (int(version) >= 7) os += " " + version;
    else os += " 2." + version;
  }
  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:70);
  exit(0);
}
if (" FTP server (EMC-SNAS: " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'EMC Celerra File Server');
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (" Tenor Multipath Switch FTP server (Version VxWorks" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'Tenor Multipath Switch');
  set_kb_item(name:"Host/OS/FTP/Type", value:"switch");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if ("(Compaq Tru64 UNIX Version " >< banner)
{
  # nb: Tru64 UNIX version 5.1A and 5.1B both report 5.60 in the FTP banner;
  #     I'm not clear if we can trust the version generally.
  os = "Tru64 UNIX";
  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:70);
  exit(0);
}
if (
  " VxWorks FTP server (VxWorks" >< banner ||
  egrep(pattern:" VxWorks \((VxWorks *)?[0-9.]+\) FTP server", string:banner)
)
{
  os = "VxWorks";
  match = eregmatch(pattern:" VxWorks \((VxWorks *)?([0-9][0-9.]+)\) FTP server", string:banner);
  if (!isnull(match)) os += " " + match[2];

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:70);     # nb: keep low as VxWorks is used in a lot of embedded kit.
  exit(0);
}
if (" QNXNTO-ftpd" >< banner)
{
  os = "QNX";
  if ("QNXNTO-ftpd 20081216" >< banner) os += " 6.5.0 SP1";
  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:95);
  exit(0);
}
if ("QTCP at " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'IBM OS/400');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}
if (egrep(string: banner, pattern: " AXIS .+ FTP Network Print Server .+ ready"))
{
  match = eregmatch(pattern:" AXIS ([0-9][^ ]+) FTP Network Print Server .+ ready", string:banner);
  if (isnull(match)) os = "AXIS Print Server";
  else os = "AXIS " + match[1] + " Print Server";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"printer");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (egrep(string: banner, pattern: " (AXIS|Axis) .+ Network Camera .+ ready"))
{
  match = eregmatch(pattern:" (AXIS|Axis) ([A-Z]?[0-9][^ ]+)( (Fixed Dome|PTZ))? Network Camera ([0-9][0-9.]+ \(.+\)) ready", string:banner);
  if (!match) os = "AXIS Network Camera";
  else os = "AXIS " + match[2] + " Network Camera with firmware " + match[5];

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"webcam");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (egrep(string: banner, pattern: " NetBotz FTP Server .+ ready"))
{
  set_kb_item(name:"Host/OS/FTP", value:"NetBotz");
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (" COT IAS2+net FTP server" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"COT Interface Adapter System");
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:95);
  exit(0);
}
if (" MSA2012sa  RAID Controller B" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"HP StorageWorks MSA2012sa");
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:95);
  exit(0);
}
if (egrep(pattern:" FS-[0-9]+(DN|MFP) FTP server", string:banner))
{
  set_kb_item(name:"Host/OS/FTP", value:'Kyocera Printer');
  set_kb_item(name:"Host/OS/FTP/Type", value:"printer");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (
  " KONICA MINOLTA FTP server" >< banner ||
  " KONICAMINOLTA FTP server" >< banner
)
{
  set_kb_item(name:"Host/OS/FTP", value:'Konica Minolta Digital Copier/Printer');
  set_kb_item(name:"Host/OS/FTP/Type", value:"printer");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
if (" FTP server (MikroTik " >< banner)
{
  os = "MikroTik RouterOS";

  match = eregmatch(pattern:" FTP server \(MikroTik ([0-9][0-9.]+)\)", string:banner);
  if (!isnull(match)) os += " v" + match[1];

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"router");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:95);
  exit(0);
}
if (" FTP server (NetApp " >< banner)
{
  match = eregmatch(string:banner, pattern:"FTP server \(NetApp Release ([0-9][^ ]+) ");
  if (!isnull(match))
  {
    set_kb_item(name:"Host/OS/FTP", value:"NetApp Release "+match[1]);
    set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
    set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  }
  else
  {
    set_kb_item(name:"Host/OS/FTP", value:"NetApp");
    set_kb_item(name:"Host/OS/FTP/Confidence", value:70);
    set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  }
  exit(0);
}
if (egrep(pattern:" SHARP (AR|MX)-.+ FTP server", string:banner))
{
  match = eregmatch(pattern:" SHARP ((AR|MX)-[^ ]+) Ver ([0-9][^ ]+) FTP server", string:banner);
  if (isnull(match))
  {
    os = "Sharp Printer";
    conf = 80;
  }
  else
  {
    os = "Sharp " + match[1] + " printer with firmware " + match[2];
    conf = 90;
  }

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"printer");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:conf);
  exit(0);
}
if ("Check Point FireWall-1 Secure FTP" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Check Point GAiA");
  set_kb_item(name:"Host/OS/FTP/Type", value:"firewall");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:75);
  exit(0);
}
if ("Welcome to SX-3000GB." >< banner)
{
  os = "Linux Kernel 2.6 on Silex SX-3000GB Gigabit USB Device Server";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:75);
  exit(0);
}
if ("Cisco IronPort FTP server" >< banner)
{
  os = "AsyncOS";
  match = eregmatch(string:banner, pattern:"Cisco IronPort FTP server \(V([0-9][^ )]+)\) ready");
  if (!isnull(match)) os += ' ' + match[1];

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:86);  # nb: beat out SSH banner.
  exit(0);
}
if (egrep(pattern:"FTP server \( +4690 TCP/IP FTP", string:banner))
{
  os = "Toshiba 4690 OS";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:80);
  exit(0);
}

# Debian 3.0r6 or Gentoo w/ netkit-ftpd
if (' FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:'Linux Kernel 2.2 on Debian 3.0 (woody)\nGentoo');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
  exit(0);
}

# Debian 2.2
if (' ProFTPD 1.2.0pre10 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.2 on Debian 2.2 (potato)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 3.0
if (' ProFTPD 1.2.5rc1 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.2 on Debian 3.0 (woody)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 3.1 / Ubuntu 6.06
if (' ProFTPD 1.2.10 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:'Linux Kernel 2.4 on Debian 3.1 (sarge)\nLinux Kernel 2.6 on Ubuntu 6.06 (dapper)');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 4.0r9
if (' ProFTPD 1.3.0 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.6 on Debian 4.0 (etch)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 5.0.8 / Ubuntu 8.04
if (' ProFTPD 1.3.1 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:'Linux Kernel 2.6 on Debian 5.0 (lenny)\nLinux Kernel 2.6 on Ubuntu 8.04 (hardy)');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 6.0.3
if (' ProFTPD 1.3.3a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.6 on Debian 6.0 (squeeze)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 7.0
if (' ProFTPD 1.3.4a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.2 on Debian 7.0 (wheezy)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Debian 8.0 / and some Ubuntu
if (' ProFTPD 1.3.5 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.16 on Debian 8.0 (jessie)\nLinux Kernel 3.13 on Ubuntu 14.04 (trusty)\nLinux Kernel 3.16 on Ubuntu 14.10 (utopic)\nLinux Kernel 3.19 on Ubuntu 15.04 (vivid)\nLinux Kernel 4.2 on Ubuntu 15.10 (wily)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 10.04
if (' ProFTPD 1.3.2c Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.6 on Ubuntu 10.04 (lucid)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 10.10
if (' ProFTPD 1.3.2e Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.6 on Ubuntu 10.10 (maverick)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 11.04
if (' ProFTPD 1.3.3d Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 2.6 on Ubuntu 11.04 (natty)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 11.10
if (' ProFTPD 1.3.4rc2 Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.0 on Ubuntu 11.10 (oneiric)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 12.04
if (' ProFTPD 1.3.4a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.0 on Ubuntu 12.04 (precise)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 12.10
if (' ProFTPD 1.3.4a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.5 on Ubuntu 12.10 (quantal)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 13.04
if (' ProFTPD 1.3.4a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 3.8 on Ubuntu 13.04 (raring)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# Ubuntu 16.04 / 16.10
if (' ProFTPD 1.3.5a Server (Debian) ' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Linux Kernel 4.4 on Ubuntu 16.04 (xenial)\nLinux Kernel 4.8 on Ubuntu 16.10 (yakkety)");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

# NAS4Free
if ('(nas4free FTP Server)' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"FreeBSD Kernel on NAS4Free");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 70);
  set_kb_item(name:"ftp/nas4free", value:TRUE);
  exit(0);
}

# Silver Peak Systems
# 220 Silver Peak restricted FTP service
if (' Silver Peak restricted FTP service' >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Silver Peak Systems");
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}
if ('xlweb FTP server' >< banner)
{
  os = "Honeywell XL Web Controller";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:80);
  exit(0);
}
if ('GuardianOS' >< banner)
{
  os = "GuardianOS";
  match = eregmatch(string:banner, pattern:"GuardianOS v([0-9.]+)");
  if (!isnull(match)) {
    os = 'GuardianOS ' + match[1];
  }

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:80);
  exit(0);
}
if (egrep(pattern:"^220 [A-Za-z0-9]+ Network Management Card AOS v",string:banner))
{
  os = "APC UPS Management Card";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:80);
  exit(0);
}
if (egrep(pattern:"^220 ZBR-[0-9]+ Version V",string:banner))
{
  os = "ZebraNet Printer FTP Server";

  set_kb_item(name:"Host/OS/FTP", value:os);
  set_kb_item(name:"Host/OS/FTP/Type", value:"printer");
  set_kb_item(name:"Host/OS/FTP/Confidence", value:80);
  exit(0);
}

}

ports_l = make_service_list(21, "Services/ftp");

foreach port (ports_l)
{
  banner = get_ftp_banner(port: port);
  if (strlen(banner) > 0 && banner =~ "^[1-5][0-9][0-9][ -]")
    test(banner: banner);
}
