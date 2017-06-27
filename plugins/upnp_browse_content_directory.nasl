#TRUSTED 0f5dec29192ca4c3f516814dace540e48db6dd172efc71185645dedb0d7b07fc7134a78bed238da7e16cc16591def382de154b36e0e595dca1130358a03015b8a010b847515f774e966487cd38626c54ecbaceb075a06b21412f05ef2c2f2ca95c3300ac6f45aface8bbee6d3488b08e36c7fe0256fc27425a493beda9b4fc3de98968a23d2c2cf0f6436cf9738eccbb3adb5efa920f773d238830ffd624bb3e13773701ed77d2e27cae1ea533bc3c34539447c666fbb7c0cce38e34a419237ab3c24e0ba754d2b548fa0c2615629537f50d862935ddd40969cdda5a125f8ed2b5d8b38749307092edca1675115877477ba91aab29c582b97d7e29ab10d11b0d5f176d3e773283cdc1c70c4e7bbbf3276672bc556f8fe63a1b5d06bb92c52322654dad6acae126aedd0baa229d9c5c877d54cae14e5763d92264da6596309cdb3464b48c3411fef93f14672ef6ab220c2ab16e371d354a8b848e7aa4560e9e4dfc60ae75590cfeec543c87eb0955d215e148dd1156c0713420737da9005ba93f9ce2c99e8d336084db52253cc3fb89f954253af59c68eea88da693900ef1eb78cc3e448f023b01d2ce17d732d809b9e542c5d0ea0bfdc762edd8b5f0d72c6069aa0ccca813557f0f2ba7f5f3c4dbddee086f228e20b308a43e22c2601b78981a4967582d00eeb15382d963eae6072984ea28cf5e0fd7a2554f45995d60c48c56

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94046);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/24");

 script_name(english: "UPnP File Share Detection");
 script_summary(english: "Lists the top level directories in the UPnP file share.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is running a file server.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device hosts a 'Content
Directory'. Therefore, an adjacent user can read shared files on the
host. This is often associated with a media server.");
 script_set_attribute(attribute:"see_also", value:"http://upnp.org/specs/av/UPnP-av-ContentDirectory-v1-Service.pdf");
 script_set_attribute(attribute:"solution", value:
"Ensure the file share is legitimate and in accordance with your
security policy.");
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
  serviceType = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/serviceType'));
  if (isnull(serviceType) || len(serviceType) != 1) continue;
  serviceType = serviceType[0];

  if ("ContentDirectory" >!< serviceType) continue;

  ctrlUrl = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/controlURL'));
  if (isnull(ctrlUrl) || len(ctrlUrl) != 1) continue;
  ctrlUrl = ctrlUrl[0];

  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:Browse xmlns:u="' + serviceType + '">' +
    '<ObjectID>0</ObjectID>' +
    '<BrowseFlag>BrowseDirectChildren</BrowseFlag>' +
    '<Filter>*</Filter>' +
    '<StartingIndex>0</StartingIndex>' +
    '<RequestedCount>10</RequestedCount>' +
    '<SortCriteria></SortCriteria>' +
    '</u:Browse>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + serviceType + '#' + 'Browse' + '"');
  resp = http_send_recv3(method: 'POST',
                         item: ctrlUrl,
                         port: port,
                         content_type: 'text/xml;charset="utf-8"',
                         add_headers: make_array('Soapaction', soapAction),
                         data: payload,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0]) continue;

  rootxml = xmlparse(resp[2]);
  if (isnull(rootxml)) continue;

  body = xml_get_child(table:rootxml, name:'s:Body');
  if (isnull(body)) continue;

  browse = xml_get_child(table:body, name:'u:BrowseResponse');
  if (isnull(browse)) continue;

  result = xml_get_child(table:browse, name:'Result');
  if (isnull(result) || len(result["value"]) == 0) continue;

  # this represents an embedded-ish xml and we have to reparse.
  rootxml = xmlparse(result["value"]);
  if (isnull(rootxml)) continue;

  local_var containers = xml_get_children(table:rootxml, name:'container');
  if (isnull(containers) || len(containers) == 0) continue;

  vuln = TRUE;
  full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
  report += '\nNessus found a browsable file share at ' + full_url + '\n';
  report += 'displaying some top level directories:\n';
  foreach(container in containers)
  {
    title = xml_get_child(table:container, name:'dc:title');
    class = xml_get_child(table:container, name:'upnp:class');
    if (!isnull(title) && !isnull(class) && 'container' >< class['value'])
    {
      report += '\t/';
      report += title['value'];
      report += '\n';
    }
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
