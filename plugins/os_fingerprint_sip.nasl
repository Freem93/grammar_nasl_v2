#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50542);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/11/26 22:06:18 $");

  script_name(english:"OS Identification : SIP");
  script_summary(english:"Identifies devices based on its SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on its
SIP banner.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified through the banner
reported by a SIP service running on it.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

global_var i, n, confidence, sip_pat, default_confidence, dev_type, name;

i = 0;
name       = make_array();             # nb: '$1', '$2', ... in the name are replaced by the corresponding match from the sip pattern
sip_pat    = make_array();
confidence = make_array();
dev_type   = make_array();

# eg, "Server: Cisco-SIPGateway/IOS-12.x"
name[i]       = "Cisco IOS $1";
confidence[i] = 80;
sip_pat[i]    = "^Cisco-SIPGateway/IOS-([0-9]+(\.[0-9]+)?)";
dev_type[i]   = "router";
i++;

# eg, "Server: Linksys/SPA9000-6.1.5"
name[i]     = "Cisco $1 Voice System";
sip_pat[i]  = "^Linksys/(SPA9000)-";
dev_type[i] = "embedded";
i++;

# eg, "Server: Linksys/SPA941-5.1.8"
name[i]     = "Cisco $1 IP Phone";
sip_pat[i]  = "^Linksys/(SPA941|SPA942|SPA962)-";
dev_type[i] = "embedded";
i++;

# eg, "Server: Linksys/PAP2T-5.1.6(LS)"
name[i]     = "Cisco $1 Phone Adapter";
sip_pat[i]  = "^Linksys/(PAP2|PAP2T|SPA2100)-";
dev_type[i] = "embedded";
i++;

# eg, "Server: Linksys/SPA2102-5.2.10"
name[i]     = "Cisco $1 Phone Adapter with Router";
sip_pat[i]  = "^Linksys/(SPA2102)-";
dev_type[i] = "router";
i++;

# eg, "Server: Linksys/SPA3102-5.1.10(GW)"
name[i]     = "Cisco $1 Voice Gateway with Router";
sip_pat[i]  = "^Linksys/(SPA3102)-";
dev_type[i] = "router";
i++;

# eg, "Server: Linksys/SPA9000-6.1.5"
name[i]     = "Cisco $1 Voice System";
sip_pat[i]  = "^Linksys/(SPA9000)-";
dev_type[i] = "embedded";
i++;

# eg, "Server: Linksys/WRP400-2.00.10"
name[i]     = "Cisco $1 Wireless Router";
sip_pat[i]  = "^Linksys/(WRP400)-";
dev_type[i] = "router";
i++;

name[i]     = "Mitel $1 IP Communications Platform";
sip_pat[i]  = "^Mitel-([0-9][^-]+)-ICP";
dev_type[i] = "pbx";
i++;

name[i]     = "Mediant $1 Media Gateway with firmware $2";
sip_pat[i]  = "^Audiocodes-Sip-Gateway-Mediant ([0-9]+)/(v\.[0-9][0-9A-Z.]+)";
dev_type[i] = "embedded";
i++;

name[i]     = "Mediatrix $1 VoIP Adaptor with firmware version $3";
sip_pat[i]  = "^(41[0-9-]+)(plus )?[ /]v?([0-9]+(\.[0-9]+)+) ";
dev_type[i] = "embedded";
i++;

name[i]     = "Mediatrix $1 VoIP Gateway with firmware version $4";
sip_pat[i]  = "^((3|44)[0-9-]+)(plus )?[ /]v?([0-9]+(\.[0-9]+)+) ";
dev_type[i] = "embedded";
i++;

name[i]     = "NEC UNIVERGE $1";
sip_pat[i]  = "^NECS(DT[7-9][0-9]0)_ITL-[0-9]+DE/[0-9]+";
dev_type[i] = "embedded";
i++;

name[i]     = "NEC UNIVERGE $1";
sip_pat[i]  = "^NEC-i (SV[7-9][0-9]00-[A-Z][A-Z] [0-9][0-9.]+/[0-9][0-9.]+)";
dev_type[i] = "embedded";
i++;

# eg, "User-Agent:Polycom HDX 8000 HD (Release - 2.6.1.3-5205)"
name[i]     = "Polycom Teleconferencing Device ($1)";
sip_pat[i]  = "^Polycom ([A-Z].+ [0-9]+[^(]*) \(Release ";
dev_type[i] = "embedded";
i++;

name[i]     = "Polycom VVX$1 with firmware $2";
sip_pat[i]  = "^PolycomVVX-VVX_([^-]+)-UA/([0-9][0-9.]+)";
dev_type[i] = "embedded";
i++;

# eg, "Server: Sipura/SPA2000-3.1.5"
name[i]     = "Sipura Analog Telephone Adapter";
sip_pat[i]  = "^Sipura/SPA2100-";
dev_type[i] = "embedded";
i++;

# eg, "PolycomSoundStationIP-SPIP_6000-UA/3.0.4.0061"
#     "PolycomSoundPointIP-SPIP_550-UA/3.2.5.0589"
name[i]     = "Polycom SoundPoint IP Phone (Sound$1 IP $2)";
sip_pat[i]  = "^PolycomSound(Point|Station)IP-SPIP_([0-9A-Z-]+)-UA/";
dev_type[i] = "embedded";
i++;

name[i]     = "Cisco TelePresence Conductor $1";
sip_pat[i]  = "^TANDBERG/[0-9]+ \(XC([^)]+)\)";
dev_type[i] = "embedded";
i++;

name[i]     = "Cisco Video Communication Server $1";
sip_pat[i]  = "^TANDBERG/[0-9]+ \(([^)]+)\)";
dev_type[i] = "embedded";
i++;

# eg, "Server: "
name[i]     = "Yealink SIP-$2 VoIP Phone";
sip_pat[i]  = "^Yealink( SIP)?-(T[0-9]+[A-Z])";
dev_type[i] = "embedded";
i++;

default_confidence = 95;
n = i;

function check_banner(banner)
{
  local_var i, j, match;

  set_kb_item(name:"Host/OS/SIP/Fingerprint", value:banner);
  for (i=0; i<n; i++)
  {
    match = eregmatch(pattern:sip_pat[i], string:banner);
    if (match)
    {
      name = name[i];
      for(j=1; j<max_index(match); j++)
        if ("$"+j >< name && match[j])
          name = str_replace(find:"$"+j, replace:match[j], string:name);

      if (confidence[i]) confidence = confidence[i];
      else confidence = default_confidence;

      set_kb_item(name:"Host/OS/SIP", value:name);
      set_kb_item(name:"Host/OS/SIP/Confidence", value:confidence);
      set_kb_item(name:"Host/OS/SIP/Type", value:dev_type[i]);
      exit(0);
    }
  }
}

udp_ports = get_kb_list("Services/udp/sip");
tcp_ports = get_kb_list("Services/sip");

if (!isnull(udp_ports))
{
  foreach port (make_list(udp_ports))
  {
    banner = get_kb_item_or_exit("sip/banner/udp/"+port);
    check_banner(banner:banner);
  }
}
if (!isnull(tcp_ports))
{
  foreach port (make_list(tcp_ports))
  {
    banner = get_kb_item_or_exit("sip/banner/"+port);
    check_banner(banner:banner);
  }
}

exit(0, "Nessus was not able to identify the OS from a SIP service banner.");
