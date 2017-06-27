#TRUSTED a53d4b18a34ac8c922dd9f8135806538c63fbdb00e1e8e276463a9e7eb21e2ada5a2532b009b9a57e4542fb555077520faec8cb622ad216b124814efbb53e577331ed04b5c8e554486ca578f726c9973990721fb93bdf8fa00521109de5631b8f93e80e5dbdb932f96a2ec768450da79de77a16fd34edf30b240691e0bf42a799148d14a782f5973e8035d01201c9f0c438f63e11b092989454b9cdba0b145c457e74cf86c5033034d653aa14eae34b0dfa075e24c1bb6d7f2448ee332cd74484a8f02369c468a7424e98123a9a0b42e670ea21c8dd31f82f68a4d319275f6c3223def1fa0c8e2d29fbb4bc693291c58c703005536fbbc3570b0f0bcb5139088d78caf49fb47bd827cba7d2e59684db15432bef367029d19385a61599f7ae6a5aa35b6bcca3aede94f5673440229c7c04552ff4420560f99efbb6d48ac86d417eeecdd39e9ee3949d23b18079ebcddfd3c08fa9f87a9c388d87555658580f217756c41885594dea475941885e9690d4b0bfc1bba48f8ca9e2f330539206441109b5624ba84e4d4939cf9040fea53c5ea14414eaf9b90b8c15162e1c35da3f5b269cd6251ced5c0c37849391c0a17ee7d66d5562a5ceddf644f46d39723f16913aa8c52c8236292137227e5e250daf60f5fca8b41249513ee4cddc692a8c48fcd03fc7f2d6c88a90bdd3dad58a9cc0094017d3b10e62712914f26d9f67eb49643

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35712);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/05");

 script_name(english:"Web Server UPnP Detection");
 script_summary(english:"Grabs the UPnP XML description file.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server provides UPnP information.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to extract some information about the UPnP-enabled
device by querying this web server. Services may also be reachable
through SOAP requests.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Universal_Plug_and_Play");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "upnp_search.nasl");
 script_require_keys("upnp/location");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include("xml_func.inc");
include('audit.inc');

##
# Queries the remote host for the provided item and
# verifies that it appears to serve XML.
# @param port the port to query
# @param item the page to request from the server
# @return the XML page or null
##
function get_devdescr(port, item)
{
  if (empty_or_null(item)) return NULL;
  # Disable the keepalive; the Windows Network Sharing UPNP server doesn't like the keepalive
  http_disable_keep_alive();
  local_var r = http_send_recv3(method:"GET",
                                port:port,
                                item:item,
                                host:get_host_ip(), # this must be an IP address
                                exit_on_fail:FALSE);

  if (!isnull(r) && '200 OK' >< r[0] && '<?xml version="1.0"' >< r[2])
  {
    set_kb_item(name:'upnp/' + url_split["port"] + '/www/banner', value:r[1]);
    return r[2];
  }
  return NULL;
}

##
# Stores an XML value into the KB. By default the value will be
# stored in 'upnp/port/name', but if 'key' is provided the value
# will be stored at 'upnp/port/key/name'
#
# @param xml an xml tree to extract the value from
# @param name the name of the value in the xml tree
# @param port the port we are operatin on
# @param key [optional] an extended KB name
# @ret a textual representation of the stored data
##
function store_xml_item(xml, name, port, key)
{
    local_var rep = "";
    local_var result = xml_get_child(table:xml, name:name);
    if (!isnull(result))
    {
      if (isnull(key))
      {
        if (!isnull(result['value']))
          set_kb_item(name:'upnp/'+ port +'/' + name, value: result['value']);
      }
      else
      {
        if (!isnull(result['value']))
          set_kb_item(name:'upnp/'+ port + '/' + key + '/' + name, value: result['value']);
      }

      rep = (name + ": " + result["value"] + '\n');
    }
    return rep;
}

##
# Parses the service list in order to collect the URLs needed for
# API, control, and event gathering.
#
# @param device the device XML
# @param port the port we are operating on
# @return rep a string representation of what was found
##
function do_service_list(device, port)
{
  local_var rep = "";
  local_var service_list = xml_get_child(table:device, name:'serviceList');
  if (isnull(service_list)) return rep;

  local_var services = xml_get_children(table:service_list, name:"service");
  if (isnull(services)) return rep;

  local_var service;
  foreach(service in services)
  {
    local_var serviceId = xml_get_child(table:service, name:'serviceId');
    if (isnull(serviceId) || len(serviceId['value']) == 0) continue;
    set_kb_item(name:'upnp/'+ port + '/service', value:serviceId['value']);

    local_var key = 'service/' + serviceId['value'];
    rep += ('ServiceID: ' + serviceId['value'] + '\n');
    rep += '\t';
    rep += store_xml_item(xml:service, name:'serviceType', port:port, key:key);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'controlURL', port:port, key:key);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'eventSubURL', port:port, key:key);
    rep += '\t';
    rep += store_xml_item(xml:service, name:'SCPDURL', port:port, key:key);
  }

  return rep;
}

##
# Looks through the provided xml for the top level device fields (which will
# be displayed in the report). Also, locates the service fields.
#
# @param xml - the xml data
# @param port - the port we are scanning
# @return rep - the extracted fields in a format usable with 'security_report'
##
function parse_devdescr(xml, port)
{
  if (isnull(xml)) return NULL;

  local_var rep = NULL;
  local_var rootxml = xmlparse(xml);
  local_var device = xml_get_child(table:rootxml, name:'device');
  if (isnull(device)) return NULL;

  # This stores the top level device information. There could be
  # other child device trees but we don't need to parse those
  rep = store_xml_item(xml:device, name:'deviceType', port:port);
  rep += store_xml_item(xml:device, name:'friendlyName', port:port);
  rep += store_xml_item(xml:device, name:'manufacturer', port:port);
  rep += store_xml_item(xml:device, name:'manufacturerURL', port:port);
  rep += store_xml_item(xml:device, name:'modelName', port:port);
  rep += store_xml_item(xml:device, name:'modelDescription', port:port);
  rep += store_xml_item(xml:device, name:'modelName', port:port);
  rep += store_xml_item(xml:device, name:'modelNumber', port:port);
  rep += store_xml_item(xml:device, name:'modelURL', port:port);
  rep += store_xml_item(xml:device, name:'serialNumber', port:port);

  rep += do_service_list(device:device, port:port);

  # Oddly, there can be an ever descending tree of deviceLists. And if
  # you are reading this true loop, I'm sure you have concerns. Good.
  # However, the loop always descends down further into the tree due
  # to the reuse of 'device' in the first xml_get_child and in the
  # return value of the second xml_get_child.
  while(TRUE)
  {
    local_var deviceList = xml_get_child(table:device, name:'deviceList');
    if (isnull(deviceList)) return rep;

    device = xml_get_child(table:deviceList, name:'device');
    if (isnull(device)) return rep;

    store_xml_item(xml:device, name:'deviceType', port:port);
    rep += do_service_list(device:device, port:port);
  }

  return rep;
}

# Loop over the locations and try to read their xml descriptions
vuln = FALSE;
locations = get_kb_list('upnp/location');
foreach(location in locations)
{
  url_split = split_url(url:location);
  if (isnull(url_split)) continue;

  # only continue if we are certain this points at our target
  if (get_host_ip() != url_split["host"]) continue;

  gd = get_devdescr(port:url_split["port"], item:url_split["page"]);
  if (isnull(gd)) continue;

  set_kb_item(name:'upnp/www', value:url_split["port"]);
  set_kb_item(name:'upnp/' + url_split["port"] + '/location', value:location);
  if (service_is_unknown(port:url_split["port"])) register_service(port:url_split["port"], proto:'www');

  parsed = parse_devdescr(xml:gd, port:url_split["port"]);
  if (isnull(parsed) || len(parsed) == 0) continue;

  report = NULL;
  vuln = TRUE;
  if (strlen(parsed)) report = strcat('\nHere is a summary of ', location, ' :\n\n', parsed);
  else report = strcat('\nBrowse ', location, ' for more information\n');
  security_report_v4(port:url_split["port"],
                     severity:SECURITY_NOTE,
                     extra:report);
}

if (vuln == FALSE) audit(AUDIT_HOST_NOT, 'affected');
