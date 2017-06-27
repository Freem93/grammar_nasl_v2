#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(48406);
  script_version ("$Revision: 1.4 $");

  script_name(english:"Misconfigured SOCKS filtering");
  script_summary(english:"Check SOCKS external IP address");

  script_set_attribute(attribute:"synopsis", value:
"Network access policies may be circumvented.");

  script_set_attribute(attribute:"description", value:
"A private network can be reached through the SOCKS proxy. 

The reachable IP address of this SOCKS proxy is public, and its
'external' address is private.  Using the SOCKS proxy, an attacker may
connect to internal machines that run on RFC1918 addresses, which are
expected to be unreachable from the public Internet." );

  script_set_attribute(attribute:"solution", value:
"Reconfigure the proxy so that it rejects connections on its public
interface or at least, enforces authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/23");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_require_ports("Services/socks4", "Services/socks5", 1080);
  script_dependencie("socks.nasl");
  exit(0);
}

#
include("global_settings.inc");
include("network_func.inc");

if (is_private_addr()) exit(0, "The target is running on a private IP address.");

pl = make_list(1080, 9050);
l = get_kb_list("Services/socks4");
if (! isnull(l)) pl = make_list(pl, l);
l = get_kb_list("Services/socks5");
if (! isnull(l)) pl = make_list(pl, l);
pl = sort(pl);

prevp = NULL;
foreach port (pl)
  if (port != prevp)
  {
    prevp = port;
    if (! get_port_state(port)) continue;
    foreach ver (make_list(4, 5))
    {
      a = get_kb_item("socks"+ver+"/external_addr/"+port);
      if (a && is_private_addr(addr: a))
      {
        m = 0;
	if (ver == 5)
	{
          m = get_kb_item("socks"+ver+"/auth/"+port);
	  # Unknown authentication method
	  if (isnull(m) && report_paranoia < 2) continue;
	}

	if (m == 0)	# No auth
	{
	  security_warning(port: port);
	  break;	# No need to report on SOCKS4 /and/ SOCKS5
	}
      }
    }
  }
