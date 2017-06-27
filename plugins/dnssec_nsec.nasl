#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(59959);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/07/26 01:27:51 $");

  script_name(english:"DNSSEC NSEC Records");
  script_summary(english: "Queries for nonexistent domains.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may disclose the hostnames of other systems.");

  script_set_attribute(attribute:"description", value:
"The remote DNSSEC server uses NSEC records for negative answers to
queries for its zone(s).  NSEC records link to additional existing
domains.  These existing domains can be used to craft further queries
that will lead to further NSEC records and thus further domains.  This
process can be repeated until all domains in the zone(s) are
disclosed.");
  
  script_set_attribute(attribute:"see_also", value:"http://blog.dest-unreach.be/2010/01/20/dnssec-the-nsec-and-nsec3-record");
  script_set_attribute(attribute:"solution", value:"Remove NSEC records for the affected zones and use an NSEC3 signing algorithm." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");
  
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("dnssec_resolver.nasl");
  script_require_keys("DNSSEC/udp/53", "DNSSEC/zone");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("dns_func.inc");

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

  if (strlen(response) <= 0)
    audit(AUDIT_RESP_NOT, 53, "a DNS request", "UDP");

  if (strlen(response) < 3 || isnull(dns_split(response)))
    audit(AUDIT_RESP_BAD, 53, "a DNS request", "UDP");

  return response;
}


function filter_affected()
{
  local_var zones;
  zones = _FCT_ANON_ARGS[0];

  local_var affected;
  affected = make_list();

  local_var zone;
  foreach zone (zones)
  {
    local_var subdomain;
    subdomain = rand_str(charset:"abcdefghijkqrstuvwxyz0123456789", length:20);

    local_var nonexistent_domain;
    nonexistent_domain = subdomain + "." + zone;

    local_var dns_request;
    dns_request = mk_dns_request(
      str    : nonexistent_domain,
      type   : DNS_QTYPE_A,
      dnssec : TRUE
    );

    local_var dns_response;
    dns_response = send_dns(dns_request);

    local_var nsec_records;
    nsec_records = dns_data_get(
      section  : "au",
      type     : DNS_QTYPE_NSEC,
      response : dns_response
    );

    if (max_index(nsec_records) == 0)
      continue;

    affected = make_list(affected, zone);
  }

  return list_uniq(affected);
}

get_kb_item_or_exit("DNSSEC/udp/53");

if (!get_udp_port_state(53))
  audit(AUDIT_PORT_CLOSED, 53, "UDP");

zones = get_kb_list_or_exit("DNSSEC/zone");
zones = make_list(zones);

affected_zones = filter_affected(zones);
if (max_index(affected_zones) <= 0)
  exit(0, "No affected zones found.");

report = '\nThe host is serving NSEC records for zones it is an authority of.\n';

# List zones
if (report_verbosity > 0)
{
  report +=
    '\nThe following affected zones were found :'+
    '\n' +
    '\n  ' + join(affected_zones, sep:'\n  ') +
    '\n'; 
}

security_warning(port:53, proto:"udp", extra:report);
