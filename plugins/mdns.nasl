#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12218);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2013/05/31 14:41:19 $");

 script_name(english:"mDNS Detection (Remote Network)");
 script_summary(english:"mDNS detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain information about the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote service understands the Bonjour (also known as ZeroConf or
mDNS) protocol, which allows anyone to uncover information from the
remote host such as its operating system type and exact version, its
hostname, and the list of services it is running. 

This plugin attempts to discover mDNS used by hosts that are not on the
network segment on which Nessus resides.");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to UDP port 5353, if desired.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("dns_func.inc");




MDNS_QU_FLAG           = 0x8000;



#
# perform single question dns query using mdns port
# return:  dns response or NULL
#
function dns_query(soc, name, type, class)
{
  local_var query, hdr, req;

  name = dns_str_to_query_txt(name);
  query = mk_query(txt:name, type:type, class:class);

  hdr['transaction_id'] = rand() & 0xffff;
  hdr['flags'] = 0x0100;
  hdr['q']     = 1;
  hdr['an_rr'] = 0;
  hdr['au_rr'] = 0;
  hdr['ad_rr'] = 0;
  req = mkdns(dns:hdr, query:query);

  send(socket:soc,data:req);

  return recv(socket:soc, length:1500);
}


#
# perform service type enumeration for @domain
#
# return:
#         - a list of advertised service types
#         - NULL if no service advertised
#
function dnssd_svc_type_enum(soc, domain)
{
  local_var name, res, type, svc_types;
  local_var contents, i, arr, rr_data;

  if(isnull(domain)) domain = 'local';

  name = '_services._dns-sd._udp.' + domain;
  res = dns_query(soc:soc, name: name, type: DNS_QTYPE_PTR, class: DNS_QCLASS_IN | MDNS_QU_FLAG);

  if(isnull(res)) return NULL;


  # parse dns response
  contents = dns_split(res);

  # check for answers
  for (i = 0 ; i < contents["an_rr"]; i++)
  {
    rr_data = contents['an_rr_data_' + i + '_data'];
    type = dns_str_get(str:rr_data,blob:res);

    # only use the first two lablels per draft-cheshire-dnsext-dns-sd.txt
    arr = split(type,sep:'.', keep:FALSE);
    type = arr[0] + '.' + arr[1];
    svc_types[i] = type;
  }

  return svc_types;
}

#
# perform service instance enumeration
#
# return:
#         - a list of advertised service instances of service @type at @domain
#         - NULL if no service instance found for @type at @domain
#
function dnssd_svc_inst_enum(soc, type, domain)
{
  local_var name, res, info, inst_name, contents;
  local_var i, seen, svc_inst, rr_name, rr_type, rr_data;

  if(isnull(domain)) domain = 'local.';

  name = type + '.' + domain;
  res = dns_query(soc:soc, name: name, type: DNS_QTYPE_PTR, class: DNS_QCLASS_IN | MDNS_QU_FLAG);

  if (!res ) return NULL;

  contents = dns_split(res);

  # answer RRs section, first pass, get all service instant names
  for (i = 0 ; i < contents["an_rr"]; i++)
  {
    rr_data = contents['an_rr_data_' + i + '_data'];
    rr_type = contents['an_rr_data_' + i + '_type'];
    # look for serivce instance name
    if(rr_type == DNS_QTYPE_PTR)
    {
       inst_name = dns_str_get(str:rr_data,blob:res);
       seen[inst_name] = 1;
    }
  }


  # look for SRV, TXT records in answer section
  for (i = 0 ; i < contents["an_rr"]; i++)
  {
    rr_data = contents['an_rr_data_' + i + '_data'];
    rr_type = contents['an_rr_data_' + i + '_type'];
    rr_name = contents['an_rr_data_' + i + '_name'];
    # look for serivce instance name
    if(rr_type == DNS_QTYPE_SRV)
    {
      info['port'] = getword(blob:rr_data, pos:4);
      info['host'] = dns_str_get(str:substr(rr_data,6, strlen(rr_data) -1), blob:res);

      if(seen[rr_name])
      {
        svc_inst[rr_name] = info;
      }
    }

    if(rr_type == DNS_QTYPE_TXT)
    {

      info['txt'] = rr_data;
      if(seen[rr_name])
      {
        svc_inst[rr_name] = info;
      }
    }
  }

  # look for SRV, TXT records in additional RRs section
  for (i = 0 ; i < contents["ad_rr"]; i++)
  {
    rr_data = contents['ad_rr_data_' + i + '_data'];
    rr_type = contents['ad_rr_data_' + i + '_type'];
    rr_name = contents['ad_rr_data_' + i + '_name'];

    # look for serivce instance name
    if(rr_type == DNS_QTYPE_SRV)
    {
      info['port'] = getword(blob:rr_data, pos:4);
      info['host'] = dns_str_get(str:substr(rr_data,6, strlen(rr_data) -1), blob:res);

      if(seen[rr_name])
      {
        svc_inst[rr_name] = info;
      }
    }

    if(rr_type == DNS_QTYPE_TXT)
    {
      info['txt'] = rr_data;
      if(seen[rr_name])
      {
        svc_inst[rr_name] = info;
      }
    }
  }


  return svc_inst;
}

#
# service discovery using dns-sd
#
# return:
#        - a list of adverstised services.
#          each service is a hash with the instance name as the key
#          services[i][<instance_name>] = info;
#          info['host']   - mdns hostname
#          info['port']   - port on which the service instance runs
#          info['txt']    - additional infomation about the service instance
#
#        - NULL if no service is advertised
#
#
function dnssd(soc, domain)
{
  local_var svc_type, svc_types, svc_inst, services, i;


  if(isnull(domain)) domain = 'local.';

  #
  # peform service type enunmeration
  #
  svc_types = dnssd_svc_type_enum(soc:soc, domain:domain);
  if(isnull(svc_types)) return NULL;


  #
  # perform service instance enumeration for each service type
  #
  i=0;
  foreach svc_type (svc_types)
  {
    svc_inst = dnssd_svc_inst_enum(soc:soc, type:svc_type, domain:domain);
    if(! isnull(svc_inst)) services[i++] = svc_inst;
  }
  return services;
}


#
#
# get HINFO record for @host
#
# return:
#         - host info if found, hinfo['cpu'], hinfo['os']
#         - NULL if HINFO record not found
#
function dns_hinfo(soc, host)
{
  local_var res, hinfo, contents, rr_type, rr_name, rr_data;
  local_var rr_data_len,i, class, pos, len;


  res = dns_query(soc:soc, name: host, type: DNS_QTYPE_HINFO, class: DNS_QCLASS_IN | MDNS_QU_FLAG);

  if(isnull(res)) return NULL;

  contents = dns_split(res);

  for (i = 0 ; i < contents["an_rr"]; i++)
  {
    rr_data = contents['an_rr_data_' + i + '_data'];
    rr_type = contents['an_rr_data_' + i + '_type'];
    rr_name = contents['an_rr_data_' + i + '_name'];
    rr_data_len = strlen(rr_data);
    if(rr_name == host && rr_type == DNS_QTYPE_HINFO)
    {
      pos = 0;
      len = ord(rr_data[pos]);
      pos++;;
      if( pos + len <= rr_data_len)
      {
        hinfo['cpu'] = substr(rr_data, pos, pos + len - 1);
        pos += len;
      }
      len = ord(rr_data[pos]);
      pos++;
      if( pos + len <= rr_data_len)
      {
        hinfo['os'] = substr(rr_data, pos, pos + len - 1);
      }

      # break on first answer
      break;
    }
  }

  return hinfo;
}


#
# dns PTR reverse lookup using the mdns port
#
# @ip     - raw IP representation
#
# return:
#         - hostname in the local domain
#         - NULL if mdns is not running
#
function dns_ptr_lookup(soc, ip)
{

  local_var name, res, i,hexb, contents;
  local_var rr_name, rr_type, rr_data, hostname;

  # ipv6
  if(strlen(ip) == 16)
  {
    for (i = 15; i >= 0; i--)
    {
      hexb = hexstr(ip[i]);
      name += hexb[1] + '.' + hexb[0] + '.';
    }
    name += 'ip6.arpa.';
  }
  # ipv4
  else if(strlen(ip) == 4)
  {
    name = ord(ip[3]) + '.' + ord(ip[2]) + '.' + ord(ip[1]) + '.' + ord(ip[0]) + '.in-addr.arpa.';
  }
  else return NULL;

  res = dns_query(soc:soc, name: name, type: DNS_QTYPE_PTR, class: DNS_QCLASS_IN | MDNS_QU_FLAG);

  if(isnull(res)) return NULL;

  contents = dns_split(res);

  for (i = 0 ; i < contents["an_rr"]; i++)
  {
    rr_data = contents['an_rr_data_' + i + '_data'];
    rr_type = contents['an_rr_data_' + i + '_type'];
    rr_name = contents['an_rr_data_' + i + '_name'];
    if(rr_name == name && rr_type == DNS_QTYPE_PTR)
    {
      hostname = dns_str_get(str:rr_data,blob:res);

      # break on first answer
      break;
    }
  }
  return hostname;
}


#
# The script code starts here
#

port = 5353;
if(!get_udp_port_state(port))exit(0, "port " + port + " not open.");

soc = open_sock_udp(port);
if ( ! soc ) exit(0, "open_sock_udp() failed on port " + port + ".");

# try to get the mDNS hostname of the target
hostname = dns_ptr_lookup(soc:soc, ip: get_host_raw_ip());

#
# try to get the advertised services
#
services_info = NULL;

services = dnssd(soc:soc);
foreach service (services)
{
  # service instances of a given service
  foreach inst (keys(service))
  {
    info = service[inst];
    services_info += '    o Service name      : '+ inst + '\n' +
                     '      Port number       : ' + info['port'] + '\n';

    if(isnull(hostname)) hostname = info['host'];
  }
}


if(hostname)
{
  set_kb_item(name:"mDNS/hostname", value:hostname);

  report = 'Nessus was able to extract the following information :\n\n' +
           '  - mDNS hostname       : ' + hostname + '\n\n';

  if(! isnull(services_info))
    report += '  - Advertised services :\n' + services_info + '\n';

  # try to query the host info
  hinfo = dns_hinfo(soc:soc, host:hostname);

  if(! isnull(hinfo))
  {
    set_kb_item(name:"mDNS/cpu", value:hinfo['cpu']);
    set_kb_item(name:"mDNS/os",  value:hinfo['os']);

    report += '  - CPU type            : ' + hinfo['cpu'] + '\n' +
              '  - OS                  : ' + hinfo['os']  + '\n';
  }
  register_service(port:port, proto:"mdns", ipproto:"udp");

  # this is only considered an info leak if the target isn't on the
  # same subnet as Nessus
  if (islocalnet())
  {
    set_kb_item(name:'/tmp/mdns/' + port + '/report', value:report);
    set_kb_item(name:'/tmp/mdns/report', value:TRUE);
  }
  else
    security_warning(port:port, proto:"udp", extra:report);
}
else exit(1, "Could not get the mDNS hostname.");
