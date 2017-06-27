# Copyright 2002 by John Lampe...j_lampe@bellsouth.net
# thanks for signatures and packet dumps from Matt N., William Craig,
# Bill King, jay at kinetic dot org,  HD Moore
#
# Modifications by rd: don't use forge_udp_packet() but use a regular
# udp socket instead ; use Nessus's SNMP functions, don't hardcode the
# use of the "public" SNMP community. Use SNMP/sysDesc is present already,
# simplified the search through the sysDesc string.
#
#

#
# See the Nessus Scripts License for details
#
#

include("compat.inc");

if (description)
{
 script_id(11026);
 script_version("$Revision: 1.74 $");
 script_cvs_date("$Date: 2014/08/19 16:08:22 $");

 script_name(english:"Wireless Access Point Detection");
 script_summary(english:"Detects Wireless APs.");

 script_set_attribute(attribute:"synopsis", value:"The remote host is a wireless access point.");
 script_set_attribute(attribute:"description", value:
"Nessus has determined that the remote host is a wireless access point
(AP).

Ensure that proper physical and logical controls are in place for its
use. A misconfigured access point may allow an attacker to gain access
to an internal network without being physically present on the
premises. If the access point is using an 'off-the-shelf'
configuration (such as 40 or 104 bit WEP encryption), the data being
passed through the access point may be vulnerable to hijacking or
sniffing.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/09");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2014 John Lampe & Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("snmp_sysDesc.nasl", "http_version.nasl", "os_fingerprint.nasl");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

type = get_kb_item("Host/OS/Type");
if ( type && type == "wireless-access-point" )
{
  type_desc = string(
    "\n",
    "Nessus has classified this device as a wireless access point based on\n",
    "its OS fingerprint.\n"
  );
  security_note(port:0, extra:type_desc);
  exit(0);
}

# list of NMAP tcp fingerprints which indicate a WAP (broken)
# current list as of nmap-3.50

tcpfinger[1] = "2Wire Home Portal 100 residential gateway";
tcpfinger[2] = "Aironet AP4800E";
tcpfinger[3] = "Apple Airport Extreme Base Station";
tcpfinger[4] = "BenQ Wireless Lan Router";
tcpfinger[5] = "Cisco 360 Access Point";
tcpfinger[6] = "Cisco 1200 access point";
tcpfinger[7] = "Cisco Aironet WAP";
tcpfinger[8] = "Cisco AP1220";
tcpfinger[9] = "Datavoice 3Com WAP";
tcpfinger[10] = "D-Link 704P Broadband Gateway or DI-713P WAP";
tcpfinger[11] = "D-Link DI-713P Wireless Gateway";
tcpfinger[12] = "D-Link DI-series, Sitecom BHS WAP";
tcpfinger[13] = "D-Link DRC-1000AP or 3com Access Point 2000";
tcpfinger[14] = "D-Link DWL-5000AP";
tcpfinger[15] = "D-Link, SMC, Tonze, or US Robotics wireless broadband router";
tcpfinger[16] = "Fiberline WL-1200R1";
tcpfinger[17] = "Linksys WET-11";
tcpfinger[18] = "Linksys BEFW11S4 WAP or BEFSR41 router";
tcpfinger[19] = "Linksys WAP11 Wireless AP";
tcpfinger[20] = "Linksys WAP11 or D-Link DWL-900+";
tcpfinger[21] = "Linksys, D-Link, or Planet WAP";
tcpfinger[22] = "Netgear DG824M WAP";
tcpfinger[23] = "Netgear FM144P";
tcpfinger[24] = "Netgear MR314";
tcpfinger[25] = "Netgear MR814";
tcpfinger[26] = "Panasonic network camera or SMC WAP";
tcpfinger[27] = "Planet WAP 1950 Wireless Access Point";
tcpfinger[28] = "SMC Barricade or D-Link DL-707 Wireless Broadband Router";
tcpfinger[29] = "SMC Barricade Wireless Broadband Router";
tcpfinger[30] = "SMC Barricade DSL Router/Modem/Wireless AP";
tcpfinger[31] = "SMC Barricade Router";
tcpfinger[32] = "Symbol/Spectrum24 wireless AP";
tcpfinger[33] = "US Robotics USR8022 broadband wireless router";
tcpfinger[34] = "US Robotics broadband router";
tcpfinger[35] = "Zcomax Wireless Access Point";
tcpfinger[36] = "ZoomAir IG-4165 wireless gateway";
# Wireless Bridges
tcpfinger[37] = "Aironet 630-2400";
tcpfinger[38] = "Aironet Wireless Bridge";
tcpfinger[39] = "ARLAN BR2000E V5.0E Radio Bridge";
tcpfinger[40] = "BreezeCOM BreezeACCESS wireless bridge";
tcpfinger[41] = "Cisco AIR-WGB340";
tcpfinger[42] = "Cisco WGB350";
tcpfinger[43] = "Linksys WET-11 wireless ethernet bridge";
tcpfinger[44] = "Linksys WGA54G";
tcpfinger[45] = "Proxim Stratum MP wireless bridge";
# This one will cause lots of false positives since the full signature is:
#  Embedded device: HP Switch, Copper Mountain DSL Concentrator, Compaq
#  Remote Insight Lights-Out remote console card, 3Com NBX 25 phone
#  system or Home Wireless Gateway, or TrueTime NTP clock
tcpfinger[46] = "3Com NBX 25 phone system or Home Wireless Gateway";


os = get_kb_item("Host/OS");
if( os )
{
  for (i=1; tcpfinger[i]; i = i + 1)
  {
	if (tcpfinger[i] >< os )
        {
		type_desc = string(
                  "\n",
                  "Nessus has classified this device as a wireless access point based on\n",
                  "its TCP/IP fingerprint. That is, many hardware devices can be\n",
                  "categorized based on their response to certain TCP/IP stimulus\n",
                  "packets. Nessus maintains a database of known responses (or\n",
                  "fingerprints) which it has used to detect this device. The exact\n",
                  "fingerprint which triggered this alert is :\n",
                  "\n",
                  "  ", tcpfinger[i], "\n"
                );
		security_note(port:0, extra:type_desc);
		exit(0);
	}
  }
}

# try to find APs via web management interface
port = get_http_port(default:80);

sigs = make_list(
# "WLAN",    # SMC, risky
 "SetExpress.shm",   #cisco 350
 "DAP-1353",        # D-Link Access Point.
 "D-Link DI-1750",
 "belkin54g",
 'realm="DI-624"',
 'realm="DIR-855"',
 'realm="DIR-825"',
 'realm="DIR-665"',
 'realm="DIR-655"',
 'realm="DGL-4500"',
 'realm="DIR-660"',
 'realm="DIR-685"',
 'realm="DAP-1555"',
 'realm="DAP-1522"',
 'realm="DIR-628"',
 'realm="DIR-625"',
 'realm="DAP-1350"',
 'realm="DAP-1360"',
 'realm="DHP-W306AV"',
 'realm="DIR-515"',
 'realm="DIR-615"',
 'realm="DIR-632"',
 'realm="DIR-815"',
 'realm="DIR-412"',
 'realm="DIR-501"',
 'realm="DIR-601"',
 'realm="WBR-2310"',
 'realm="WBR-1310"',
 'realm="DGL-4300"',
 'realm="DWL-G730AP"',
 'realm="DWL-G820"',
 'realm="DWL-G700AP"',
 'realm="DWL-G2100AP"',
 'realm="DWL-G800AP"',
 'realm="DVA-G3810BN"',
 'realm="DIR-330"',
 "D-Link DI-824",
 "D-Link DI-784",
 "D-Link DI-774",
 "D-Link DI-764",
 "D-Link DI-754",
 "D-Link DI-714",
 "D-Link DI-713",
 "D-Link DI-624",
 "DI-624+",
 "D-Link DI-614",
 "D-Link DI-524",
 "D-Link DI-514",
 "D-Link DSA-3100",
 "Cisco AP340",
 "Cisco AP350",
 "Linksys WAP",
 'Linksys WRT',
 'Linksys WRE',
 "Linksys BEFW",
 "Linksys WPG",
 "Linksys WRV",
 "SOHO Version",
 'realm="BUFFALO WBR-G54"',
 'WWW-Authenticate: Basic realm="R2 Wireless Access Platform"',
 'realm="MR814',
 'realm="FM114P',
 'realm="MA101',
 'realm="MR314',
 'realm="ME102',
 'realm="DG824M',
 'realm="DG834G',
 'realm="PS111W',
 'realm="CG814M',
 'realm="FVM318',
 'realm="ME103',
 'realm="HE102',
 'realm="HR314',
 'realm="Ral-WAP3"',    # Linksys WRT-54G Wireless-G Router, from Jeff Mercer
 'realm="WG101',
 'realm="WG302',
 'realm="WG602',
 'realm="WGR614',
 'realm="FWAG114',
 'realm="FM114P',
 'realm="WKPC',
 'realm="WCG',
 'realm="WET',
 'realm="BEFW',
 'realm="WAP11',
 'realm="WAP51',
 'realm="WAP54',
 'realm="WAP55',
 'realm="WRT54',
 'realm="WRT54G',
 'realm="WRT55',
 'realm="WRT300',
 'realm="WRV200',
 'realm="WRTSL',
 'realm="Linksys WAG200G "',	# Ming the trailing space!
 "BCM430",		# Broadcom chips (?)
 "OfficePortal 1800HW",
 "HomePortal 180HW",
 "Portal 1000HG",
 "Portal 1000HW",
 "Portal 1000SW",
 "Portal 1700HG",
 "Portal 1700HW",
 "Portal 1700SG",
 "HomePortal 180HG",
 "HomePortal 2000",
 "Wireless 11a/b/g Access Point",
 "AT-WA1004G",
 "AT-WA7500",
 "AT-WL2411",
 "RTW020",
 "RTA040W",
 "RTW010",
 "The setup wizard will help you to configure the Wireless",
 'realm="Access-Product',
 "USR8054",
 "WGR614",
 "WGR624",
 "Linksys WET11",
 "wireless/wireless_tab1.jpg",
 "wireless/use_as_access_point",
 "Gateway 11G Router",
 "Gateway 11B Router",
 "MN-500",
 "MN-700",
 "MN-510",
 "SBG900",
 "SBG1000",
 "WA840G",
 "WL1200-AB",
 "WL5400AP",
 # jwlampe@nessus.org adds on 5.19.2006
 "LANCOM Wireless L-11",
 "LANCOM L-54g Wireless",
 "LANCOM L-54ag Wireless",
 "Linksys BEFW11",
 "Server: DCS-",
 "Cisco WGB350",
 "Wi-LAN AWE",
 'WWW-Authenticate: Basic realm="DD-WRT"',
 'WWW-Authenticate: Basic realm="802.11g Access Point"',
 'WWW-Authenticate: Basic realm="Linksys BEFW11S4 V4"',
 'EdgeCore Enterprise Access Point',
 'id="wireless_table" summary="wireless clients table">',    # DD-WRT
 'ealm="TP-LINK Wireless Dual Band ',
 'ealm="TP-LINK Wireless G ',
 'ealm="TP-LINK Wireless Lite N ',
 'ealm="TP-LINK Wireless N ',
 'VPN Firewall FVS318N',
 'realm="ClickShare"');

# jwlampe@nessus.org adds on 10.31.2006
GenericSigs = make_list("WIRELESS", "ACCESS POINT", "Wireless", " AP ", "Access Point", "WEP", "WPA", "SSID", "Service Set ID", "Beacon", "RTS", "CTS", "54G", "54 Mbps", "108 Mbps", "11 Mbps", "Ad Hoc", "Ad-hoc", "Wired Equivalent Privacy", "Infrastructure Mode", "Frame Burst", "DTIM", "Fragmentation Threshold", "TX Antenna", "RX Antenna", "Hotspot", "802.11", "2.4GHz", "2.412", "2.417", "2.422", "2.427", "2.432", "2.437", "2.442", "2.447", "2.452", "2.457", "2.462", "2.467", "2.472", "2.484");

generic_counter = 0;
GenMatches = make_list();


if(get_port_state(port))
{
    soc = http_open_socket(port);
    if(soc)
    {
  	send(socket:soc, data:http_get(item:"/", port:port));
  	answer = http_recv(socket:soc);
  	http_close_socket(soc);
  	if (answer)
  	{
    	    foreach sig (sigs)
    	    {
          	if ( sig >< answer )
  	  	{
	    banner_desc = string(
              "\n",
              "Nessus has determined that this device is an access point based on a\n",
              "phrase found on the server's default web page. That is, Nessus\n",
              "maintains a list of commonly-used technical phrases which can be\n",
              "associated with wireless technologies. When Nessus encounters these\n",
              "phrases during a scan, a determination is made regarding the nature of\n",
              "the device. The exact phrase which Nessus flagged on is :\n",
              "\n",
              "  ", sig, "\n"
            );
	    security_note(port:0,  extra:banner_desc);
              	    exit(0);
          	}
    	    }
	    foreach sig (GenericSigs)
	    {
		if ( sig >< answer )
		{
		    generic_counter++;
		    GenMatches = make_list(GenMatches, sig);
		}
	    }
  	}
     }
}

if (generic_counter >= 4)
{
    generic_desc = string(
      "\n",
      "Nessus has determined that this device is an access point based on a\n",
      "phrase found on the server's default web page. That is, Nessus\n",
      "maintains a list of commonly-used technical phrases which can be\n",
      "associated with wireless technologies. When Nessus encounters these\n",
      "phrases during a scan, a determination is made regarding the nature of\n",
      "the device. In this case, Nessus has determined that the device may\n",
      "be running a wireless device with an administrative interface enabled. \n",
      "This is a very common configuration for Access Points. The exact\n",
      "phrases which Nessus flagged on were :\n",
      "\n"
    );

    foreach sig (GenMatches)
	generic_desc = string(generic_desc, "  - ", sig, "\n");

    security_note(port:0,  extra:generic_desc);

}

# try find APs via ftp
port = 21;
ftppos[0] = "Cisco BR500";
ftppos[1] = "WLAN AP";
ftppos[2]= "ireless";
 # jwlampe@nessus.org adds on 5.19.2006
ftppos[3] = "DCS-5300G";
ftppos[4] = "DCS-5300W";
ftppos[5] = "DCS-6620G";


if(get_port_state(port))
{
soc = open_sock_tcp(port);
if (soc) {
  r = recv_line(socket:soc, length:512);
  close(soc);
  if (r) {
      for (i=0; ftppos[i]; i = i + 1) {
          if ( ftppos[i] >< r )
	  {
               ftp_desc=string(
                 "\n",
                 "Nessus has determined that this device is an access point based on \n",
                 "its FTP service banner, which is :\n",
                 "\n",
                 "  ", ftppos[i], "\n"
               );
               security_note(port:0, extra:ftp_desc);
               exit(0);
          }
      }
  }
 }
}

# try to find APs via telnet
port = 23;
telnetpos[0] = "DCS-3220G telnet daemon";
telnetpos[1] = "DCS-5300G Telnet Daemon";
telnetpos[2] = "DCS-5300W Telnet Daemon";
telnetpos[3] = "DCS-6620G telnet daemon";
telnetpos[4] = "ink Corp. Access Point";
telnetpos[5] = "WLSE";
telnetpos[6] = "Cisco BR500E";
telnetpos[7] = "Cisco WGB350";
telnetpos[8] = "Wi-LAN AWE";
telnetpos[9] = "Lucent Access Point";
telnetpos[10]= "Wireless DSL Ethernet Switch";
telnetpos[11]= "LANCOM 1811 Wireless DSL";
telnetpos[12]= "LANCOM Wireless";
telnetpos[13] = "LANCOM L-54";
telnetpos[14] = "ADSL Wireless Router";
telnetpos[15] = "Motorola Broadband Wireless";
telnetpos[16] = "Trango Broadband Wireless";
telnetpos[17] = "Wi-LAN Hopper";
telnetpos[18] = "WANFleX Access Control";
telnetpos[19] = "Access Point Console";
telnetpos[20] = "Samsung SWL-3300AP";
telnetpos[21] = "Samsung SWL-4000";
telnetpos[22] = "Samsung SWL-6100";
telnetpos[23] = "FortiWiFi-";
telnetpos[24] = "WLAN Access Point login";
telnetpos[25] = "Wireless AP Manager Console";
telnetpos[26] = "Wireless Ethernet Adapter";
telnetpos[27] = "Avaya-Wireless-AP";
telnetpos[28] = "ORiNOCO-AP-";
telnetpos[29] = "WAP-";
telnetpos[30] = "USR5450";
telnetpos[31] = "Raylink Access Point";
telnetpos[32] = "Access Point Configuration";
telnetpos[33] = "Aircess -";
telnetpos[34] = "Netro Airstar shell";
telnetpos[35] = "Proxim AP Configuration";
telnetpos[36] = "AXXCELERA BROADBAND WIRELESS";
telnetpos[37] = "DD-WRT v";
telnetpos[38] = "ProCurve Wireless Access Point";

if ( get_port_state(port) )
{
    soc = open_sock_tcp(port);
    if (soc)
    {
    	r = recv_line(socket:soc, length:512);
	if (r)
	{
	    # the first 'line' might be eaten up by the telnet init
	    # We need to recv one more time to get the banner
	    r2 = recv_line(socket:soc, length:512);
	    close(soc);
	    r = r + r2;
      	    for (i=0; telnetpos[i]; i = i + 1)
            {
          	if ( telnetpos[i] >< r )
          	{
                    telnet_desc=string(
                      "\n",
                      "Nessus has determined that this device is an access point based on\n",
                      "its telnet banner, which is :\n",
                      "\n",
                      "  ", telnetpos[i], "\n"
                    );
               	    security_note(port:0, extra:telnet_desc);
               	    exit(0);
          	}
      	    }
  	}
	else
	{
	    close(soc);
	}
     }
}

# try to find APs via snmp port (rely on them leaving public community string)

#
# Solaris comes with a badly configured snmpd which
# always reply with the same value. We make sure the answers
# we receive are not in the list of default values usually
# answered...
#
function valid_snmp_value(value)
{
 if("/var/snmp/snmpdx.st" >< value)return(0);
 if("/etc/snmp/conf" >< value)return(0);
 if( (strlen(value) == 1) && (ord(value[0]) < 32) )return(0);
 return(1);
}

community = get_kb_item("SNMP/community");
if(!community)exit(0);

if(get_udp_port_state(161))
{
 soc = open_sock_udp(161);

# put char string identifiers below
 snmppos[0]="AP-";                     # Compaq AP
 snmppos[1]="Base Station";
 snmppos[2]="WaveLan";
 snmppos[3]="WavePOINT-II";# Orinoco WavePOINT II Wireless AP
 snmppos[4]="AP-1000";     # Orinoco AP-1000 Wireless AP
 snmppos[5]="Cisco BR500"; # Cisco Aironet Wireless Bridge
 snmppos[6]="ireless";
 snmppos[7]="Internet Gateway Device"; # D-Link (fp-prone ?)
 snmppos[8]="802.11b";
 snmppos[9]="802.11g";
 snmppos[10]="802.11a";
 snmppos[11]="802.11n";
 snmppos[12]="Access Point";
 snmppos[13]="V-M200 - Hardware revision";  # HP M200

# create GET sysdescr call

mydata = get_kb_item("SNMP/sysDesc");
if(!mydata) {
 snmpobjid = raw_string(0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00);
 version = raw_string(0x02 , 0x01 , 0x00);
 snmplen = strlen(community) % 256;
 community = raw_string(0x04, snmplen) + community;
 pdu_type = raw_string(0xa0, 0x19);
 request_id = raw_string(0x02,0x01,0xde);
 error_stat = raw_string(0x02,0x01,0x00);
 error_index = raw_string(0x02,0x01,0x00);
 tie_off = raw_string(0x05,0x00);

 snmpstring = version + community + pdu_type + request_id + error_stat
+ error_index + raw_string(0x30,0x0e,0x30,0x0c,0x06,0x08) + snmpobjid +
tie_off;

 tot_len = strlen(snmpstring);
 tot_len = tot_len % 256;

 snmpstring = raw_string(0x30, tot_len) +  snmpstring;

 send(socket:soc, data:snmpstring);

 mydata = recv(socket:soc, length:1025);
 if(strlen(mydata) < 48)exit(0);
 if(!mydata)exit(0);

 check_val = valid_snmp_value(value:mydata);
 if (!check_val) exit(0);
}

flag = 0;

for (psi=0; snmppos[psi]; psi = psi + 1) {
        if(snmppos[psi] >< mydata) {
            snmp_desc=string(
              "\n",
              "Nessus has determined that this device is an access point based on\n",
              "its system description obtained via SNMP, which is :\n",
              "\n",
              snmppos[psi], "\n"
            );
            security_note(port:0, extra:snmp_desc);
            exit(0);
        }
 }
}
