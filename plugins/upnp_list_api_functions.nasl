#TRUSTED 5069dea4411748394f959180410481ddb94fe575b6133dbac852c947db03f56355c826bfb3d4fcea15f8043c29f78cd11487c9e368a67dcf9c9b9d340b0224f130c1ceb58aeb333f6be45cf8003a76a0dfca83827e8e38f9b7d596c2185976cb3e573104631c2abb991449f7c99d2ee112871b7060c5c2ad6359176bb98f8a79bdf311e9cf9e9bc28eab50c35a07540cc506ecf2972efb0068d5d2ecce3d8f8485586f90a0c0fd92f05afd3f4d675570ccd582d2c834ef957c93e57124de899cefba80601383cf8967740a915d878d9ee2eac9b9cf87cefbf396deecc7847fd0243ae3b1aabe4996cf2ac80c4d4b326b5b63bbc137f85cd2a536c39c064efdb23e18865e3a85b5ffb922a559811823c430780ce454ed06e236be99289f1b76aede5b834aed8912f66691b7c812fcb2b74a40cf45ffc8f045a9a2562d527963fe0262a65141d91c2b5abf8352affcf0fb5f7a00238cb8163035f5b00f31f0298d209620d8951653e3760388402f8315b790c62bb7d5a044848725b584c0c53e6926c3b2ff13558c220bf9a66d17f00b147791e70422619db78f6acfaf692d32a2167117ce6d48e519bd6252eee9f3add64334c3f556efe095ec571393cf2c96c7928ba1c62b5049e991f078cf5d8e5967fc1bf453d55185d7cb2b0dbd45eea981d4d2e82546bba7c2380490e5bd11c01a87b382248f23207ca1c0ca939d526805

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94047);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/24");

 script_name(english: "UPnP API Listing");
 script_summary(english: "Retrieves and parses the UPnP Service Control Protocol Document XML.");

 script_set_attribute(attribute:"synopsis", value:
"The remote server exposes a UPnP SCPD XML.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device supports a SOAP API over
UPnP. Nessus was able to retrieve and parse the UPnP Service Control
Protocol Document XML.");
 script_set_attribute(attribute:"see_also", value:"https://developer.gnome.org/gupnp/stable/glossary.html#scpd");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include("xml_func.inc");
include('audit.inc');
include('http.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');
services = get_kb_list('upnp/'+port+'/service');

report = '';
vuln = FALSE;
foreach(service in services)
{
  ctrlUrl = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/controlURL'));
  if (isnull(ctrlUrl) || len(ctrlUrl) != 1) continue;
  ctrlUrl = ctrlUrl[0];

  descriptionURL = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/SCPDURL'));
  if (isnull(descriptionURL) || len(descriptionURL) != 1) continue;
  descriptionURL = descriptionURL[0];

  resp = http_send_recv3(method: 'GET',
                         item: descriptionURL,
                         port: port,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0]) continue;

  rootxml = xmlparse(resp[2]);
  if (isnull(rootxml)) continue;

  actionList = xml_get_child(table:rootxml, name:'actionList');
  if (isnull(actionList)) continue;

  actions = xml_get_children(table:actionList, name:'action');
  if (isnull(actions)) continue;

  func_names = '';
  foreach(action in actions)
  {
    name = xml_get_child(table:action, name:'name');
    if (isnull(name)) continue;

    func_names += '\tFunction name: ' + name['value'] + '\n';
  }

  if (len(func_names) == 0) continue;

  vuln = TRUE;
  full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
  report += '\nThe UPnP service at ' + full_url + ' implements the following functions :\n' + func_names;
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
