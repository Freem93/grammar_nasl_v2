#TRUSTED 10fd4175140999f82cced1ffc86952063d66ea517c42c49a751b7a88dacf8877122ea0c53887eb37dc89107a433a54be3fcf08631d84f4668577e2a53d9e4e733eb8c740d17e57f9ba31e51624f95c99498c5c6361e20f74c56f53fafb7e8386f79a3e1b5dbafd9505ae664c361b440eede7f3009e1842c3c7f6c27f286b510df248910be08a8b26dff0746787b23c87921ab36b08d68f23cf1e0ccc400f13b17fc8a0bafc38e48ec9add7a6808159704bc3e61ff938023ebe3a4e0f92ae055caefe25fe451c1555f4b2c37723df0ff1f289771baba1fc69170c0081457f06ce5eada412639a1a82f63be4d7b73b13414c2efa2f63db8592868b79552cd5bad8fdac64ae73f891d96a96f34615155cdf4be06f5609c21c0cb70c96bb71b2381cdb0861e305ee13f30941f3c8a13deeabbb36341caf62a390b538c563d6991cd8553589c855e37119ef960da9a3107305b05434574ce8ffafa282eaf13be8f479d92d3f5b339855c688ac39affdc559d68e6cdf9216fc713b9894c094271dad7dd3199d87ca75dec9fca866f58f9da43149bee4854966de9a0f143afbeec26593247b9d8891101f60c81486b6a73027b6ad5baaac7b7a9114c6cc7f8dd0fa0a8ca9acddabf0aabe58947ab077dabc9b3458730f527d6fa2b7e663efa1fbd0e8c81616fee089cb0071b964aad626f87ecb5b56e031cd17eee69f0cda6ef09a2775

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35711);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/13");

 script_name(english: "Universal Plug and Play (UPnP) Protocol Detection");
 script_summary(english: "Sends a UPnP M-SEARCH request.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device supports UPnP.");
 script_set_attribute(attribute:"description", value:
"The remote device answered an SSDP M-SEARCH request. Therefore, it
supports 'Universal Plug and Play' (UPnP). This protocol provides
automatic configuration and device discovery. It is primarily intended
for home networks. An attacker could potentially leverage this to
discover your network architecture.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Universal_Plug_and_Play");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol");
 script_set_attribute(attribute:"see_also", value:"http://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt");
 script_set_attribute(attribute:"solution", value:
"Filter access to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');

if (TARGET_IS_IPV6) exit(0, "This plugin does not support IPV6 hosts.");
if (!get_udp_port_state(1900)) audit(AUDIT_PORT_CLOSED, 1900, 'UDP');

##
# This function extracts the advertised URL. If the ip address in the URL matches
# the host address then we will try to register it as a 'www' service.
#
# @param response - The response to the M-SEARCH request
# @param location - The regex match to a location-type field
# @return the parsed URL (ie http://192.168.1.1:9090/gateway.xml)
##
function parse_location(response, location)
{
    location = chomp(location[1]);
    local_var address = eregmatch(string:response, pattern:'http[s]?://(\\d+\\.\\d+.\\d+\\.\\d+):(\\d+)', icase:TRUE);
    if (!isnull(address) && len(address) == 3)
    {
        set_kb_item(name:'upnp/location', value:location);
        return location;
    }
    return NULL;
}

bind_result = bind_sock_udp();
if (isnull(bind_result)) audit(AUDIT_SOCK_FAIL, "udp");

msearch = 'M-SEARCH * HTTP/1.1\r\n' +
          'HOST: 239.255.255.250:1900\r\n' +
          'MAN: "ssdp:discover"\r\n' +
          'MX: 1\r\n' +
          'ST: ssdp:all\r\n' +
          '\r\n';

responses = make_list();
for (i = 0; i < 3 && len(responses) == 0; i++)
{
    # From what I've seen, there are a variety of uPnP servers that will only
    # respond if the destination address is the multicast address. However,
    # there are others that will respond to a direct (ie host ip) request.
    # Since Nessus scans can go beyond the range of the multicast address, and
    # we still want all responses if the host is within multicast range, we will
    # just fire off two requests here.
    sendto(socket:bind_result[0], data:msearch, dst:'239.255.255.250', port:1900);
    sendto(socket:bind_result[0], data:msearch, dst:get_host_ip(), port:1900);

    # look for a response. Since this is UDP we will attempt to resend this
    # if we get no response. We also set a timeout that matches the MX record
    # in our M-SEARCH request
    resp = recvfrom(socket:bind_result[0], port:bind_result[1], src:get_host_ip(), timeout:1);
    while(!isnull(resp))
    {
        if (resp[1] ==  get_host_ip()) responses = make_list(responses, resp[0]);
        resp = recvfrom(socket:bind_result[0], port:bind_result[1], src:get_host_ip(), timeout:1);
    }
}

close(bind_result[0]);
if (len(responses) == 0) audit(AUDIT_NOT_LISTEN, "UPnP", 1900, "UDP");
else register_service(port: 1900, ipproto: "udp", proto: "ssdp");

# Combine any duplicates due to UDP madness.
responses = list_uniq(responses);

# For each entry find the 'location', 'SECURELOCATION.UPNP.ORG', 'server',
# and 'urn'.
locations = make_list();
servers = make_list();
usns = make_list();
foreach(response in responses)
{
    set_kb_item(name: 'upnp/m-search', value: chomp(response));

    location = eregmatch(string:response, pattern:'\r\nLOCATION:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(location))
    {
        location = parse_location(response:response, location:location);
        if(!isnull(location)) locations = make_list(locations, location);
    }

    location = eregmatch(string:response, pattern:'\r\nSECURELOCATION.UPNP.ORG:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(location))
    {
        location = parse_location(response:response, location:location);
        if(!isnull(location)) locations = make_list(locations, location);
    }

    server = eregmatch(string:response, pattern:'\r\nSERVER:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(server))
    {
        server = chomp(server[1]);
        servers = make_list(servers, server);
        set_kb_item(name:'upnp/server', value:server);
    }

    usn = eregmatch(string:response, pattern:'\r\nUSN:[ ]*(.+)\r\n', icase:TRUE);
    if (!isnull(usn))
    {
        if ('::' >< usn[1])
        {
            # Only list URN that have the interface they are implementing. For ex:
            # uuid:9764ead3-00d3-5576-9c4a-9d6895a4cd57::upnp:rootdevice
            usn = chomp(usn[1]);
            usns = make_list(usns, usn);
        }
    }
}

report = 'The device responded to an SSDP M-SEARCH request with the following locations :\n\n';
locations = list_uniq(locations);
foreach(location in locations)
{
    report += ('    ' + location + '\n'); 
}

report += '\nAnd advertises these unique service names :\n\n';
usns = list_uniq(usns);
foreach(usn in usns)
{
    report += ('    ' + usn + '\n'); 
}
report += '\n';

security_report_v4(port:1900,
                   proto:"udp",
                   severity:SECURITY_NOTE,
                   extra:report);
