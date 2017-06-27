#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90149);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/24 15:39:53 $");

  script_cve_id("CVE-2016-82007");
  script_xref(name:"TRA", value:"TRA-2016-03");

  script_name(english:"Microsoft DNS Server Inverse Query Buffer Over-Read");
  script_summary(english:"Performs a DNS inverse query.");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host has enabled inverse query.");
  script_set_attribute(attribute:"description", value:
"The Microsoft DNS server running on the remote host has inverse query
functionality enabled. It is, therefore, affected by a buffer
over-read error in the dns.exe!answerIQuery() function due to a
failure to correctly parse the Resource Record in an inverse query
packet. An unauthenticated, remote attacker can exploit this to cause
a denial of service or to disclose information.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-03");
  script_set_attribute(attribute:"solution", value:
"Remove or set the Windows REG_DWORD registry key
  'HKLM\System\CurrentControlSet\Services\DNS\Parameters\
    EnableIQueryResponseGeneration'
to zero.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("dns_version.nasl", "os_fingerprint.nasl");
  script_require_ports("DNS/udp/53", "DNS/tcp/53");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");
include("dump.inc");


function dns_rr(name, type, class, ttl, rdlen, rdata)
{
  local_var rr;
 
  if(isnull(name) || isnull(type))
    return NULL;

  if(isnull(class))
    class = DNS_QCLASS_IN;
  if(isnull(ttl))
    ttl = 3600;
  if(isnull(rdlen))
    rdlen = strlen(rdata);
  
  name = dns_str_to_query_txt(name);
  rr =  name + mkword(type) + mkword(class) + mkdword(ttl) + mkword(rdlen)
        + rdata; 
  return rr;
}

port = 53;

# Make sure DNS server is detected
if(get_kb_item("DNS/udp/"+port))
  do_tcp = 0;
else if(get_kb_item("DNS/tcp/"+port))
  do_tcp = 1;
else
  audit(AUDIT_NOT_LISTEN, "DNS Server", port);

# Make sure it's Windows DNS server
dns_version = get_kb_item("dns_server/version");
if (dns_version)
{
  if ("Microsoft DNS" >!< dns_version) 
    audit(AUDIT_NOT_LISTEN, "Microsoft DNS Server", port);
}
else
{
  os = get_kb_item_or_exit("Host/OS"); 
  if("Windows" >!< os)
    audit(AUDIT_OS_NOT, "Windows");
}

dns["transaction_id"] = rand() % 65535;
dns["flags"]	      = 0x0910;
dns["an_rr"]	      = 1;

name = 'any_name'; 
body = dns_rr(name:name,type: DNS_QTYPE_A, rdata:'\xc0\xa8\x01\x01'); 
packet = mkdns(dns:dns,query:body);

if(do_tcp)
{
  soc = open_sock_tcp(port);
  packet = mkword(strlen(packet)) + packet;
}
else
  soc = open_sock_udp(port);

if ( ! soc )
  audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:packet);
if(do_tcp)
{
  r  = recv(socket: soc, length: 2, min: 2);
  if (strlen(r) == 2)
  {
    len = getword(blob:r, pos:0);
    r  = recv(socket: soc, length: len);
  }
  else
    audit(AUDIT_RESP_BAD, port);
}
else
  r = recv(socket:soc, length:4096);
  
close(soc);
if(r)
{
  ret = dns_split(r);
  if(isnull(ret))
    exit(1, 'Failed to parse a DNS response.');
  
  rc = ret['flags'] & 0xf;

  # IQuery not enabled (default configuration)
  if (rc == 4)
  {
    exit(0, 'Inverse query is not enabled on the remote Windows DNS server, which is therefore not affected.');
  } 
  # IQuery enabled, 
  # return code depends on the memory content right after the IQuery packet. 
  else if(rc == 0 || rc == 1)
  {
    extra = NULL;
    if(rc == 0)
    {
      data = ret['q_data_0_name'];
      if (data =~ "^\[.+\]$")
      {
        data -= '[';
        data -= ']';
        data = hexdump(ddata:data);
        extra = 'Nessus was to able to extract the following memory content right after the DNS inverse query packet :\n' 
                + data; 
      }
    }
    proto = 'udp';
    if (do_tcp) proto = 'tcp';
    security_warning(port:port, extra:extra, proto:proto); 
  }
  # Unexpected
  else 
    audit(AUDIT_RESP_BAD, port, 'a DNS inverse query, RCODE: ' + rc);
}
else 
  audit(AUDIT_RESP_NOT, port, 'a DNS inverse query'); 
