#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

#
# Thanks to the following persons for having sent additional
# SNMP communities over time :
#
# Javier Fernandez-Sanguino, Axel Nennker and the following references :
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
#
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
#
# http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
# http://www.nessus.org/u?b471b647
#

if (description)
{
 script_id(10264);
 script_version("$Revision: 1.105 $");
 script_cvs_date("$Date: 2016/01/19 15:40:44 $");

 script_cve_id(
  "CVE-1999-0186",
  "CVE-1999-0254",
  "CVE-1999-0472",
  "CVE-1999-0516",
  "CVE-1999-0517",
  "CVE-1999-0792",
  "CVE-2000-0147",
  "CVE-2001-0380",
  "CVE-2001-0514",
  "CVE-2001-1210",
  "CVE-2002-0109",
  "CVE-2002-0478",
  "CVE-2002-1229",
  "CVE-2004-0311",
  "CVE-2004-1474",
  "CVE-2010-1574"
 );
 script_bugtraq_id(
  177,
  973,
  986,
  2112,
  3758,
  3795,
  3797,
  4330,
  6825,
  7081,
  7212,
  7317,
  9681,
  10576,
  11237,
  41436
  );
 script_osvdb_id(
  209,
  1871,
  3985,
  5770,
  6738,
  6856,
  8076,
  8807,
  8817,
  8843,
  9770,
  10206,
  10427,
  10860,
  11964,
  58147,
  66120,
  92010,
  92011,
  92012,
  92013,
  92014,
  92015
 );
 script_xref(name:"CERT", value:"732671");
 script_xref(name:"EDB-ID", value:"20892");

 script_name(english:"SNMP Agent Default Community Names");
 script_summary(english:"Checks default community names of the SNMP agent.");

 script_set_attribute(attribute:"synopsis", value:
 "The community names of the remote SNMP server can be guessed.");
 script_set_attribute(attribute:"description",value:
"It is possible to obtain the default community names of the remote
SNMP server.

An attacker can use this information to gain more knowledge about the
remote host or to change the configuration of the remote system (if
the default community allows such modifications).");
 script_set_attribute(attribute:"solution",value:
"Disable the SNMP service on the remote host if you do not use it,
filter incoming UDP packets going to this port, or change the default
community string.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "1998/11/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:snmp:snmp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");

 script_dependencies("find_service2.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_timeout(540);                   # max number of community names to test * 10.
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("snmp_func.inc");
include ("audit.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# if we don't know which versions of SNMP are supported, try both v2c and v1.
# Protect against the fact that this host may be configured for SNMPv3 auth.
if ( get_kb_item("SNMP/version") )
{
  if ( get_kb_item("SNMP/version_v1") )
    vers = make_list(0);
  else
    vers = make_list(1);
}
else vers = make_list(1, 0);

port = get_kb_item("SNMP/port");
if(!port){
	port = 161;
	snmp_not_detected = TRUE;
	}
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

default = make_list("private", "public", "cisco");
extra = make_list(
  "0392a0",
  "ANYCOM",
  "Cisco router",
  "ILMI",
  "NoGaH$@!",
  "OrigEquipMfr",
  "Secret C0de",
  "TENmanUFactOryPOWER",
  "admin",
  "agent",
  "agent_steal",
  "all",
  "all private",
  "apc",
  "blue",
  "c",
  "cable-docsis",
  "cascade",
  "cc",
  "comcomcom",
  "community",
  "core",
  "default",
  "diag",
  "freekevin",
  "fubar",
  "guest",
  "hp_admin",
  "ilmi",
  "internal",
  "localhost",
  "manager",
  "manuf",
  "monitor",
  "openview",
  "password",
  "proxy",
  "regional",
  "riverhead",
  "rmon",
  "rmon_admin",
  "secret",
  "security",
  "snmp",
  "snmpd",
  "system",
  "test",
  "tivoli",
  "write",
  "xyzzy",
  "yellow"
);
if (thorough_tests) default = make_list(default, extra);


comm_list = "";
comm_number = 0;
foreach community (default)
{
  soc[community] = open_sock_udp(port);
  if (!soc[community]) continue;
}


for ( i = 0 ; i < 2 ; i ++ )
{
 foreach community ( default )
 {
  foreach ver ( vers )
  {
    set_snmp_version( version:ver );

    if ( isnull(soc[community]) ) continue;
    rep = snmp_request_next(socket:soc[community], timeout:1 + i, community:community, oid:"1.3");
    if (!isnull(rep))
    {
      if (
        # Sun ...
        (rep[1] != "/var/snmp/snmpdx.st") && (rep[1] != "/etc/snmp/conf") &&
        # HP MSL 8048
        "1.3.6.1.2.1.11.6.0" != rep[0]
      )
      {
        set_kb_item(name:"SNMP/default/community", value:community);
        comm_list += strcat('  - ' + community + '\n');
        comm_number++;
      }
      close(soc[community]);
      soc[community] = NULL;
    }
  }

  # once we've received a response, keep using the same SNMP version in all remaining requests
  if (!isnull(rep)) vers = make_list(ver);
 }
}

foreach community (keys(soc) )
{
 if ( !isnull(soc[community]) ) close(soc[community]);
}


# We're done with actual sends, so set the SNMP_VERSION back, if needed.
reset_snmp_version();

if (comm_number > 0)
{
  if (comm_number > 5)
    report = string (
      "\n",
      "The remote SNMP server replies to more than 5 default community\n",
      "strings. This may be due to a badly configured server or an SNMP\n",
      "server on a printer."
    );
  else
  {
    if (comm_number == 1) s = "";
    else s = "s";
    report = string (
      "\n",
      "The remote SNMP server replies to the following default community\n",
      "string", s, " :\n",
      "\n",
      comm_list
    );
  }


 if ( snmp_not_detected ) register_service( port:161, proto:"snmp", ipproto:"udp");


  if (comm_number != 1 || (comm_number == 1 && "public" >!< comm_list))
    security_hole(port:port, extra:report, protocol:"udp");
}
