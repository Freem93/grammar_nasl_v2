#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43829);
  script_version("$Revision: 1.6 $");

  script_name(english:"Kerberos Information Disclosure");
  script_summary(english:"Tries to get the realm name and server time");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Kerberos server is leaking information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to retrieve the realm name and/or server time of the
remote Kerberos server."
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/01/08");
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_require_ports(88);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("kerberos_func.inc");


# globals
KRB_ERROR = 0x7e;
reqrealm = SCRIPT_NAME;

port = 88;
if (!get_port_state(port))
  exit(0, "Port "+port+" is not open.");


function printable_time()
{
  local_var rawtime, y, M, d, h, m, s;
  rawtime = _FCT_ANON_ARGS[0];

  y = substr(rawtime, 0, 3);
  M = substr(rawtime, 4, 5);
  d = substr(rawtime, 6, 7);
  h = substr(rawtime, 8, 9);
  m = substr(rawtime, 10, 11);
  s = substr(rawtime, 12, 13);

  return y+'-'+M+'-'+d+' '+h+':'+m+':'+s+' UTC';
}


# send/receives an AS-REQ message. doesn't exit() if no response is received,
# since some Kerberos servers don't respond to certain kinds of messages
function asreq_send_recv()
{
  local_var asreq, soc, req, len, res;
  asreq = _FCT_ANON_ARGS[0];
  if (isnull(asreq)) return NULL;

  soc = open_sock_tcp(port);
  if (!soc)
    exit(1, "Failed to open a socket on port "+port+".");

  req = mkdword(strlen(asreq)) + asreq;
  send(socket:soc, data:req);

  res = recv(socket:soc, length:4);
  if (isnull(res))
  {
    debug_print("The service on port "+port+" failed to respond.");
    return NULL;
  }

  len = getdword(blob:res, pos:0);
  if ( len > 65535 ) exit(0);
  res = recv(socket:soc, length:len);
  if (strlen(res) < len)
    exit(1, "Truncated packet received on port "+port+".");

  close(soc);

  return res;
}

function parse_asreq_res()
{
  local_var data, buf, seq;
  data = _FCT_ANON_ARGS[0];

  buf = der_decode(data:data, pos:0);
  if (buf[0] != KRB_ERROR)
    exit(1, "Unexpected tag received: "+hexstr(mkbyte(buf[0])));

  seq = der_parse_sequence(seq:buf[1], num:13);
  if (isnull(seq))
    exit(1, "Unable to parse sequence.");

  return seq;
}


#
# execution starts here
#

# First send a request that should get us the server time, no matter
# which product is being used
service = der_encode_name(type:2, name1:"krbtgt", name2:reqrealm);
req_body = der_encode_kdc_req_body(realm:reqrealm, service:service);
encoded = der_encode_kdcreq(pvno:5, msg_type:0x0A, req_body:req_body);
asreq = der_encode (tag:0x6A, data:encoded);

res = asreq_send_recv(asreq);
if (isnull(res))
  exit(1, "No response received from port "+port+".");

seq = parse_asreq_res(res);
stime = der_parse_data(tag:0x18, data:seq[4]);
realm = der_parse_data(tag:0x1b, data:seq[9]);
if (realm && realm == reqrealm) realm = NULL;

# Then send a request that that will get us the realm name.  Only works
# with some Kerberos servers

#KDC_REQ_BODY
list[0] = der_encode(tag:0x03, data:raw_string (0x00,0x40,0x00,0x00,0x10));
list[1] = NULL;
list[2] = der_encode_string(string:reqrealm);
list[3] = NULL;
list[4] = NULL;
list[5] = der_encode_time(time:"20370913024805Z");
list[6] = der_encode_time(time:"20370913024805Z");
list[7] = der_encode_int(i:rand());
list[8] = der_encode_list(list:der_encode_int (i:11));
list[9] = NULL;
kdc_req_body = der_encode_sequence(seq:list);

#AS_REQ
l[0] = NULL;
l[1] = der_encode_int(i:5);
l[2] = der_encode_int(i:0x0a);
l[3] = NULL;
l[4] = kdc_req_body;
encoded = der_encode_sequence (seq:l);
asreq = der_encode (tag:0x6A, data:encoded);

res = asreq_send_recv(asreq);
if (!isnull(res))
{
  seq = parse_asreq_res(res);
  stime = der_parse_data(tag:0x18, data:seq[4]);
  realm = der_parse_data(tag:0x1b, data:seq[9]);
}

if (!isnull(stime) || !isnull(realm))
{
  if (report_verbosity > 0)
  {
    report = '\nNessus gathered the following information :\n\n';

    if (!isnull(stime))
      report += '  Server time  : '+printable_time(stime)+'\n';
    if (!isnull(realm))
      report += '  Realm        : '+realm+'\n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'Unable to obtain time and/or realm of the Kerberos server on port '+port+'.');
