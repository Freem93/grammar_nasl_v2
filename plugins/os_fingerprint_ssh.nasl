#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25287);
  script_version("$Revision: 1.103 $");
  script_cvs_date("$Date: 2016/12/05 16:24:19 $");

  script_name(english:"OS Identification : SSH");
  script_summary(english:"Checks SSH banners.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
SSH banner.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system type and version
by looking at the SSH banner returned by the remote server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

ports = get_kb_list("Services/ssh");
if ( isnull(ports) )
 ports = make_list(22);
else
 ports = make_list(ports);

port = ports[0];
if ( ! get_port_state(port) ) exit(0);


banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

set_kb_item(name:"Host/OS/SSH/Fingerprint", value:banner);

confidence = 95;
#
# If SSH is not running on port 22, decrease the confidence level
# as it might be a port forwarded somewhere else
#
if ( port != 22  || max_index(ports) > 1 ) confidence -= 20;

sshtext = get_kb_item('SSH/textbanner/'+port);

if ( banner =~ "^SSH-[0-9.]+-SSH-[0-9.]+-(.*)" ) exit(1, "Malformed SSH banner"); # https://discussions.nessus.org/message/7830#7830

if (banner =~ "SSH-[0-9][0-9.]+-xxxxxxx")
{
 set_kb_item(name:"Host/OS/SSH", value:"FortiOS on Fortinet FortiGate");
 set_kb_item(name:"Host/OS/SSH/Type", value:"firewall");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-FortiSSH_" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Fortinet");
 set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-Sun_SSH_2\.0"  )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 11");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-Sun_SSH_1\.0\.1"  )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 9");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-Sun_SSH_1\.1"  )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 10");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~  "^SSH-2\.0-Sun_SSH_1\.0$" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 8");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.5p1 FreeBSD" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 4.10');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1 FreeBSD" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 5.3\nFreeBSD 5.4\nFreeBSD 5.5');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.2p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 6.0\nFreeBSD 6.1');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.5p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 6.2\nFreeBSD 6.3\nFreeBSD 7.0');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_5\.1p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 7.3\nFreeBSD 7.4\nPanasas\n');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_5\.2p1 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 8.0');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_5\.4p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 8.1\nFreeBSD 8.2\nAsyncOS');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_5\.4p1_hpn13v11 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 8.3');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_5\.8p2_hpn13v11 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 9.0\nFreeBSD 9.1');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_6\.1_hpn13v11 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 8.4');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_6\.2_hpn13v11 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 9.2\nAsyncOS');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_6\.4_hpn13v11 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 10.0');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_7\.2 FreeBSD-" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 10.3');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.+-OpenSSH_6\.6\.1_hpn13v11 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 9.3\nFreeBSD 10.1\nFreeBSD 10.2');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 4.10 (warty)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.9p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 5.04 (hoary)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.1p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 5.10 (breezy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.2p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 6.06 (dapper)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.3p2.*ubuntu")
{
 confidence -= 5;
 set_kb_item(name:"Host/OS/SSH", value:'Linux Kernel 2.6 on Ubuntu 6.10 (edgy)\nLinux Kernel 2.6 on Ubuntu 7.04 (feisty)');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.6p1 Debian-5ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 7.10 (gutsy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.7p1 Debian-8ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 8.04 (hardy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.1p1 Debian-5ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 9.04 (jaunty)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.1p1 Debian-6ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 9.10 (karmic)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.3p1 Debian-3ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 10.04 (lucid)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.5p1 Debian-4ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 10.10 (maverick)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.8p1 Debian-1ubuntu")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu 11.04 (natty)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.8p1 Debian-7ubuntu")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.0 on Ubuntu 11.10 (oneiric)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.9p1 Debian-5ubuntu")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.0 on Ubuntu 12.04 (precise)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.0p1 Debian-3ubuntu")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.5 on Ubuntu 12.10 (quantal)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.1p1 Debian-3ubuntu")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.8 on Ubuntu 13.04 (raring)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.2p2 Ubuntu-6")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.11 on Ubuntu 13.10 (saucy)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.6p1 Ubuntu-2")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.13 on Ubuntu 14.04 (trusty)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.6\.1p1 Ubuntu-8")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.16 on Ubuntu 14.10 (utopic)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.7p1 Ubuntu-5ubuntu1(\.[1-4])?$")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.19 on Ubuntu 15.04 (vivid)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.9p1 Ubuntu-2")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 4.2 on Ubuntu 15.10 (wily)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_7\.2p2 Ubuntu-4")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 4.4 on Ubuntu 16.04 (xenial)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_7\.3p1 Ubuntu-1")
{
  set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 4.8 on Ubuntu 16.10 (yakkety)");
  set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}

# nb: BlueCat uses a hardened version of Debian so it must be identified
#     before that OS.
else if ('\nBlueCat Networks Proteus ' >< sshtext)
{
  os = "Linux Kernel";
  product = "BlueCat Address Manager";  # nb: Proteus is an older name for the product.

  match = eregmatch(pattern:'\\\nServer Version ([0-9]+\\.[0-9]+.*)\\\n', string:sshtext);
  if (isnull(match))
  {
    os += ' on a ' + product;
  }
  else
  {
    proteus_version = match[1];
    if (proteus_version =~ "^3\.7\.") kernel_version = ' 2.6';
    else kernel_version = '';

    os += kernel_version + ' on a ' + product + ' with Proteus software release ' + proteus_version;
  }

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_1\.2\.3.* Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.2 on Debian 2.2 (potato)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.4p1 Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.2 on Debian 3.0 (woody)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1 Debian.*sarge")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.4 on Debian 3.1 (sarge)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.3p2 Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Debian 4.0 (etch)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.1p1 Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Debian 5.0 (lenny)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_5\.5p1 Debian-6")
{
 set_kb_item(name:"Host/OS/SSH", value:'Linux Kernel 2.6 on Debian 6.0 (squeeze)\nHP 3PAR');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence-10);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.0p1 Debian-4")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.2 on Debian 7.0 (wheezy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_6\.7p1 Debian-5")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 3.16 on Debian 8.0 (jessie)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner == "SSH-2.0-Unknown" )
{
 set_kb_item(name:"Host/OS/SSH", value:"NetEnforcer Application Bandwidth Manager");
 set_kb_item(name:"Host/OS/SSH/Type", value:"packet-shaper");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:15);
}
else if ( banner =~ "SSH-.* SSH Secure Shell Tru64 UNIX" )
{
 # SSH.com SSH only exist for Tru64 5.1
 # and we can't distinguish 5.1 minor versions.
 confidence -= 20;
 set_kb_item(name:"Host/OS/SSH", value:"Tru64 UNIX 5.1");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-2\.0-mpSSH_0\." )
{
 set_kb_item(name:"Host/OS/SSH", value:"HP Integrated Lights Out");
 set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:78);
}
else if ( banner =~ "^SSH-2\.0-XPSSH" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Enterasys XP Switch");
 set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:45);
}
# SSH-2.0-3.2.0 F-SECURE SSH - Process Software MultiNet
# SSH-1.99-3.1.0 F-SECURE SSH - Process Software TCPware
# SSH-2.0-3.2.0 SSH Secure Shell OpenVMS V5.5
else if (banner =~ "^(SSH-(1\.99|2\.0)-.* Process Software (MultiNet|TCPware)|SSH-(1\.99|2\.0)-.* SSH Secure Shell OpenVMS)")
{
 set_kb_item(name:"Host/OS/SSH", value:"OpenVMS");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value: 76);
}
else if ( banner =~ "SSH-[0-9.]+-Cisco-1\.25" )
{
 set_kb_item(name:"Host/OS/SSH", value:'CISCO IOS 15\nCISCO IOS 12\nCisco IOS XE\nCISCO PIX');
 set_kb_item(name:"Host/OS/SSH/Type", value:"router");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:69);
}
else if ( banner =~ "SSH-[0-9.]+-Cisco-2\.0" )
{
 set_kb_item(name:"Host/OS/SSH", value:'Cisco IOS XR');
 set_kb_item(name:"Host/OS/SSH/Type", value:"router");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:75);
}
else if (banner =~ "SSH-[0-9.]+-SSH_v[0-9.]+@force10networks\.com")
{
 set_kb_item(name:"Host/OS/SSH", value:'Dell Force10 Operating System');
 set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:75);
}
else if (banner =~ "SSH-[0-9.]+-OpenSSH_[0-9.]+(p[0-9]+)?\.RL$")
{
 set_kb_item(name:"Host/OS/SSH", value:'Dell PowerConnect Switch');
 set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:66);
}
else if ( banner =~ "SSH-[0-9.]+-OpenSSH_[0-9.]+ NetBSD_Secure_Shell-2008" )
{
 set_kb_item(name:"Host/OS/SSH", value:'NetBSD 5.0\nNetBSD 5.1\nNetBSD 5.1.3\nNetBSD 5.1.4\nNetBSD 5.1.5\nNetBSD 5.2.1\nNetBSD 5.2.2\nNetBSD 5.2.3');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:70);
}
else if ( banner =~ "SSH-[0-9.]+-OpenSSH_[0-9.]+ NetBSD_Secure_Shell-201109" )
{
 set_kb_item(name:"Host/OS/SSH", value:'NetBSD 6.0\nNetBSD 6.0.1\nNetBSD 6.0.2\nNetBSD 6.0.3\nNetBSD 6.0.4\nNetBSD 6.0.5\nNetBSD 6.0.6\nNetBSD 6.1\nNetBSD 6.1.2\nNetBSD 6.1.3\nNetBSD 6.1.4\nNetBSD 6.1.5');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:70);
}
else if (
  ereg(pattern:"SSH-[0-9.]+-ROSSSH", string:banner) ||
  # nb: the version here is not the OS' version!
  ereg(pattern:"SSH-[0-9.]+-OpenSSH_[0-9.]+_Mikrotik_v([0-9.]+)", string:banner)
)
{
  set_kb_item(name:"Host/OS/SSH", value:'MikroTik RouterOS');
  set_kb_item(name:"Host/OS/SSH/Type", value:"router");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:90);
}
else if (
  sshtext != "" &&
  'The EMC(C) version of Linux(C), used as the operating system ' >< sshtext &&
  'EMC Celerra Control Station Linux' >< sshtext
)
{
  pat = 'EMC Celerra Control Station Linux release [0-9.]+ \\(NAS ([0-9.]+)\\)';
  v = eregmatch(string: sshtext, pattern: pat);
  if (! isnull(v))
  {
    set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on an EMC Celerra Network Server version " + v[1]);
    set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
    set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
  }
  else
  {
    set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on an EMC Celerra Network Server");
    set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
    set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence - 5);
  }
}
else if (banner =~ "SSH-.*-OpenSSH_.* QNX_Secure_Shell-")
{
  os = "QNX";
  if ("QNX_Secure_Shell-20090621" >< banner) os += " 6.5.0 SP1";
  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:95);
}
else if (
  sshtext &&
  ereg(pattern:"Nexus [0-9]+[a-zA-Z]* Switch", string:sshtext)
)
{
  set_kb_item(name:"Host/OS/SSH", value:"Cisco NX-OS");
  set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if (banner =~ "SSH-.*-Data ONTAP SSH ")
{
  os = "NetApp";
  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:81);
}
else if ("Data Domain OS " >< sshtext)
{
  os = "EMC Data Domain OS";
  v = eregmatch(pattern:"Data Domain OS ([0-9.-]+)", string:sshtext);
  if (!isnull(v)) os += " " + v[1];

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:90);
}
else if (banner =~ "SSH-[0-9.]+-BNT")
{
  os = "IBM BNT";

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:90);
}
else if (banner =~ "SSH-[0-9.]+-FBLOS")
{
  os = "FBLOS";

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"load-balancer");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:70);
}
else if (banner =~ "SSH-[0-9.]+-Comware-")
{
  os = "HP Switch";     # Comware / 3Com / HP Switch

  # eg, "SSH-1.99-Comware-5.20 Release 1111P02"
  v = eregmatch(pattern:"SSH-[0-9.]+-Comware-([0-9][0-9.]+) Release ([^ ]+)", string:banner);
  if (!isnull(v)) os += " with Comware software version " + v[1] + " release " + v[2];

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:85);
}
else if (banner =~ "SSH-[0-9.]+-USHA SSHv")
{
  set_kb_item(name:"Host/OS/SSH", value:"ConnectUPS Web/SNMP Card");
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:65);
}
else if (banner =~ "SSH-[0-9.]+-DOPRA-")
{
  set_kb_item(name:"Host/OS/SSH", value:"Huawei");
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");  # nb: Huawei uses this widely across their product line.
  set_kb_item(name:"Host/OS/SSH/Confidence", value:70);
}
else if (banner =~ "SSH-[0-9.]+-IPSSH-[0-9.]+")
{
  os = "VxWorks";
  v = eregmatch(pattern:"SSH-[0-9.]+-IPSSH-([0-9.]+)", string: banner);
  if (!isnull(v)) os += " " + v[1];

  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:70);
}
else if (banner =~ "Silver Peak Systems Inc\.")
{
  os = "Silver Peak Systems";
  set_kb_item(name:"Host/OS/SSH", value:os);
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:90);
}
else if ( banner =~ "SSH-.*-NetScreen")
{
  set_kb_item(name:"Host/OS/SSH", value:"Juniper ScreenOS");
  set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
