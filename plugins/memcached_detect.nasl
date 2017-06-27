#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26197);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/04/10 15:36:34 $");

 script_name(english:"memcached Detection");
 script_summary(english:'Sends stats command to memcached');

 script_set_attribute(attribute:"synopsis", value:"memcached is running on this port.");
 script_set_attribute(attribute:"description", value:
"memcached, a memory-based object store, is listening on the remote
port.");
 script_set_attribute(attribute:"see_also", value:"http://memcached.org/");
 script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/memcached/");
 script_set_attribute(attribute:"see_also", value:"http://www.mediawiki.org/wiki/Memcached");
 script_set_attribute(attribute:"solution", value:
"If memcached is deployed in untrusted networks, it's recommended that
SASL be enabled to restrict access to authorized users.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:memcached:memcached");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("find_service2.nasl", "hazelcast_memcache_detect.nasl");
 script_require_ports(11211, "memcached/possible_port");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("memcache.inc");


# issue VERSION command using binary protocol
# cannot use STAT command as authentication is required when SASL is enabled.
function test(port)
{
  local_var	req, report, res, ret, s, ver;

  if (! get_port_state(port)) return;
  s = open_sock_tcp(port);
  if (! s) return;

  req = mcb_mk_req(cmd: MEMCACHE_CMD_VERSION);
  send(socket: s, data: req);
  res = mcb_read_resp(socket: s);
  close(s);
  if(isnull(res)) return;

  ret = mcb_parse_resp(res);
  if(isnull(ret) || ret['status'] != MEMCACHE_RESP_NO_ERROR || isnull((ver = ret['value']))) return;

  register_service(port:port, proto:"memcached");

  report = NULL;

  if (ver =~ '^[0-9]+[0-9.]+')
  {
    set_kb_item(name:'memcached/version/'+port, value:ver);
    report = '\n  Version : ' + ver + '\n';
  }

  if (report_verbosity > 0 && report) security_note(port:port, extra:report);
  else security_note(port);
}

test(port: 5701);
test(port: 11211);

ports_l = get_kb_list("memcached/possible_port");
if ( isnull(ports_l) ) exit(0);
foreach port (make_list(ports_l))
{
  hazelcast = get_kb_item('hazelcast/' + port + '/memcached');
  if ( port != 5701 && port != 11211 && isnull(hazelcast)) test(port: port);
}
