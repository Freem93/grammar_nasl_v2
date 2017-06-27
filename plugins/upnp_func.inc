#TRUSTED 188978286e34412e87b69dac3a422795d7c4903da10cdb18cfd69c0e13948eb0d30ff061f6ad1e13bfd2087e509d104a2e30875c06a6488e0c4fbff05d2f9617287d73bdfd8c4b521abf7f3b5b2287ef959431264148ee31c3cf85b2f9df91fa08f84161912e1828050382bbde36c2d676520721f827f5dd441ca4a6af130346ba53f4dc41e12752db9bbaf8b1340cd9b1cf674dd66aa00c6426f9847528e3fa93a73d648eacb7913def622e150260eab02314a35d669b15373b668412d36ccccc9e66d18d19b39035187d47ccf2205b83e560a7f817f725a02cd5a5de765df8a81d4b33c03b40616bcaeda58f7889fecd9efd5465c1325ca5372b3fc6fbc652cc7b9ffb8c1197280bb66fbcfa324ea2e7c7f71ef0ffe9ebe29b884dda5215e058305cfb04717549ae1df3c792cd4b62618b931d14ff06278867b2f74ad998bab34580fe07740856a50e362a92fc362e375a79f44ba85c223777f58e1664edf2620c63fcccb5033d6cda9795b51693290271d26cff5fe27308c4c4a87f81cdd2b40c8b22fed91cbbf9597deb519ef1537d9e362a289dc42c59b074271f6d7d4a46f5c7c9df4283e497166f0796e6d63bd24f5cae7160ee30db8588afb38c4f95c6ae4b92527dbed69452bdf65891e0e85e833533668c67dc0deeb755a4172f6ca81253834ccd2bb152a9e249968a1ff0db3e285a6e1ee63e808eda8da71592d5

# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# upnp_func.inc 
# Revision 1.3
#

##
# Finds the provided service field and extracts the
# index and control url.
# @param xml the xml describing a service
# @param service the service to locate
# @return array - the url and index
##
function upnp_svc_url(xml, svc)
{
  local_var pattern = '<serviceType>urn:schemas-upnp-org:service:' + svc + ':' + '([0-9]+)' + '</serviceType>';
  local_var service = eregmatch(string:xml, pattern:pattern, icase:TRUE);
  if (isnull(service)) return NULL;

  local_var url = eregmatch(string: xml, pattern: "<controlURL>([^<]+)</controlURL>");
  if (isnull(url)) return NULL;

  local_var ret_val = make_array();
  ret_val['url'] = url[1];
  ret_val['index'] = service[1];
  return ret_val;
}

function upnp_find_service(xml, svc)
{
  local_var p, i, u;

  while (1)
  {
    p = strstr(xml, '<service>');
    if (isnull(p)) return NULL;
    i = stridx(p, '</service>');
    u = upnp_svc_url(xml: substr(p, 9, i - 1), svc: svc);
    if (!isnull(u)) return u;
    xml = substr(p, i + 9);
  }

  return NULL;
}

function upnp_make_soap_data(action, svc, fields)
{
  local_var xml, f;

  xml = strcat('<?xml version="1.0"?>\r\n',
 '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r\n',
 '<SOAP-ENV:Body>\r\n',
 '<m:', action, ' xmlns:m="', svc, '">\r\n');

 foreach f (keys(fields))
 {
   xml = strcat(xml, '<', f, '>', fields[f], '</', f, '>\r\n');
 }
 xml = strcat(xml, '</m:', action, '>\r\n',
'</SOAP-ENV:Body>\r\n',
'</SOAP-ENV:Envelope>\r\n' );
 return xml;
}

function upnp_make_soap_req(port, url, action, svc, fields)
{
  local_var xml, rq;

  xml = upnp_make_soap_data(action: action, fields: fields, svc: svc);
  rq = http_mk_post_req(port: port, item: url, data: xml, host: get_host_ip(),
     add_headers: make_array('Content-Type', 'text/xml', 
    'SOAPAction', strcat('"', svc, '#', action, '"')) );
  rq['User-Agent'] = NULL;
  rq['Connection'] = NULL;
  rq['Pragma'] = NULL;
  rq['Accept'] = NULL;
  rq['Accept-Language'] = NULL;
  rq['Accept-Charset'] = NULL;
  rq['Cookie'] = NULL;
  rq['Date'] = NULL;
  return rq;
}


# Local Variables: **
# mode:Fundamental **
# comment-column:0 **
# comment-start: "# "  **
# End: **
