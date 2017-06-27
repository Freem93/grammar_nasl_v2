#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
    script_id(35373);
    script_version("$Revision: 1.14 $");
    script_cvs_date("$Date: 2013/11/21 15:13:27 $");

    script_name(english:"DNS Server DNSSEC Aware Resolver");
    script_summary(english:"Sends DNSSEC queries");

    script_set_attribute(attribute:"synopsis", value:
"The remote DNS resolver is DNSSEC-aware.");
    script_set_attribute(attribute:"description", value:
"The remote DNS resolver accepts DNSSEC options.  This means that it
may verify the authenticity of DNSSEC protected zones if it is
configured to trust their keys.");
    script_set_attribute(attribute:"solution", value:"n/a");
    script_set_attribute(attribute:"risk_factor", value:"None");

    script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/15");

    script_set_attribute(attribute:"plugin_type", value:"remote");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
    script_family(english:"DNS");
    script_dependencies("dns_server.nasl");
    script_require_keys("DNS/udp/53");
    exit(0);
}

#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

###
# Forms a DNS PTR request for the given IP.
#
# @anonparam ip IP address to form a PTR record request for.
#
# @return The result of mk_dns_request for formed PTR record.
##
function mk_reverse_lookup()
{
  local_var ip_octs;
  ip_octs = split(_FCT_ANON_ARGS[0], sep:".", keep:FALSE);

  local_var ip_rev;
  ip_rev  = join(ip_octs[3], ip_octs[2], ip_octs[1], ip_octs[0], sep:".");

  local_var str;
  str = ip_rev+".in-addr.arpa";

  return mk_dns_request(str:str, type:DNS_QTYPE_PTR);
}


###
# Opens udp:53 socket and sends argument. Exits on failure.
#
# @anonparam request Raw DNS request.
#
# @return Raw DNS response from remote host.
##
function send_dns()
{
  local_var request;
  request = _FCT_ANON_ARGS[0];

  local_var soc;
  soc = open_sock_udp(53);
  if (isnull(soc))
    audit(AUDIT_SOCK_FAIL, 53, "UDP");

  send(socket:soc, data:request);

  local_var response;
  response = recv(socket:soc, length:8192);

  close(soc);

  if (strlen(response) == 0)
    audit(AUDIT_RESP_NOT, 53, "a DNS request", "UDP");

  if (strlen(response) < 3 || isnull(dns_split(response)))
    audit(AUDIT_RESP_BAD, 53, "a DNS request", "UDP");

  return response;
}

##
# Retrieves DNSKEY records that the remote host is an authority for.
#
# 1. Do a reverse lookup to collect domain names.
# 2. Use those domain names to guess possible zone names.
# 3. Perform a DNSKEY request for each of those guesses.
#
# @param dnssec_required Ignore DNSKEYs from non-DNSSEC responses.
#
# @return Array of DNSKEY records.
##
function get_dnskeys(dnssec_required)
{
  # Key is zone, value is list of DNSKEY records.
  dnskeys = make_array();

  local_var request;
  request = mk_reverse_lookup(get_host_ip());

  local_var ptr_rsp;
  ptr_rsp = send_dns(request);

  local_var ptr_data;
  ptr_data = dns_data_get(section:"an", type:DNS_QTYPE_PTR, response:ptr_rsp);

  local_var zones, ptr_datum;
  zones = make_array();
  foreach ptr_datum (ptr_data)
  {
    local_var name;
    name = dns_str_get(str:ptr_datum, blob:ptr_rsp);
    zones[name] = name;

    if (strlen(name) && "." >< name)
    {
      local_var potential_zone;
      potential_zone = tolower(substr(name, stridx(name, ".") + 1));
      zones[potential_zone] = potential_zone;
    }
  }
  zones = make_list(zones);

  # DNSKEYs the host is authorative for.
  # Keys are zone names and values are DNSKEY lists.
  local_var dnskeys;
  dnskeys = make_array();
  local_var zone;
  # Collect DNSKEYs for which we are authoritative for.
  foreach zone (zones)
  {
    local_var dnskey_req;
    dnskey_req = mk_dns_request(str:zone, type:DNS_QTYPE_DNSKEY, dnssec:dnssec_required);

    local_var dnskey_rsp;
    dnskey_rsp = send_dns(dnskey_req);

    # DNSSEC records along with it?
    local_var rrsig_data;
    rrsig_data = dns_data_get(section:"an", type:DNS_QTYPE_RRSIG, response:dnskey_rsp);
    if (max_index(rrsig_data) == 0 && dnssec_required)
      continue;

    # Only record if our nameserver is authoritative for this domain.
    if ((ord(dnskey_rsp[2]) & 0x04) == 0x04)
    {
      dnskeys[zone] = dns_data_get(
        section  : "an",
        type     : DNS_QTYPE_DNSKEY,
        response : dnskey_rsp
      );
    }
  }

  return dnskeys;
}

###
# Send DNSSEC-enabled A record query to the remote host
# for www.example.com to detect DNSSEC cababilities. Exits on error.
# Note, RRSIG records wont be returned if DNS recursion is disabled.
#
# @return TRUE if provides RRSIGS on request, FALSE if not.
##
function is_dnssec_resolver()
{
  local_var dnssec_req;
  dnssec_req = mk_dns_request(str:"www.example.com", type:DNS_QTYPE_A, dnssec:TRUE);

  local_var r;
  r = send_dns(dnssec_req);

  # We look at RRSIG records instead of the "accepts DNSSEC" flag in the OPT RR
  # as the abscence of that flag does not mean the response is non-DNSSEC.
  local_var rrsig_data;
  rrsig_data = dns_data_get(section:"ad", type:DNS_QTYPE_RRSIG, response:r);

  return max_index(rrsig_data) > 0;
}

get_kb_item_or_exit("DNS/udp/53");

if (!get_udp_port_state(53))
  audit(AUDIT_PORT_CLOSED, 53, "UDP");

# NOTE: Provides false negative if recursion is disabled.
dnssec_resolver = is_dnssec_resolver();

# In the process of looking up these keys, we confirm the host supports DNSSEC.
dnskeys = get_dnskeys(dnssec_required:TRUE);

if (max_index(dnskeys) == 0 && !dnssec_resolver)
  exit(0, "DNSSEC is not supported on UDP port 53.");

security_note(port:53, proto:"udp");
set_kb_item(name:"DNSSEC/udp/53", value:TRUE);

foreach zone (keys(dnskeys))
{
  set_kb_item(name:"DNSSEC/zone", value:zone);
  foreach dnskey (dnskeys[zone])
  {
    set_kb_blob(name:"DNSSEC/zone/" + zone + "/dnskey", value:dnskey);
  }
}
