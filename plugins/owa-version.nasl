#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14255);
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/12/26 16:15:46 $");
 
 script_name(english:"Microsoft Outlook Web Access (OWA) Version Detection");
script_summary(english:"Outlook Web Access version check.");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to extract the version of Microsoft Exchange Server
installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Microsoft Exchange Server with Outlook Web Access (OWA) embeds the 
Exchange version number inside the default HTML web page. By
requesting the default HTML page, Nessus was able to extract the
Microsoft Exchange server version." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/11");
 
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook_web_access");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

exchange_vers = make_array();
exchange_vers['15']['product'] = '2013';
exchange_vers['15']['sp'] = make_array(0, '15.0.516.32', 1, '15.0.620.29', 2, '15.0.712.24', 3, '15.0.712.24', 4, '15.0.847.32', 5, '15.0.913.22', 6, '15.0.995.29');

# Exchange 2010
exchange_vers['14']['product'] = '2010';
exchange_vers['14']['sp'] = make_array(0, '14.0.639.21', 1, '14.1.218.15', 2, '14.2.247.5', 3, '14.3.123.4');

# Exchange 2007
exchange_vers['8']['product'] = '2007';
exchange_vers['8']['sp'] = make_array(0, '8.0.685.25', 1, '8.1.240.6', 2, '8.2.176.2', 3, '8.3.83.6');

# This section is for old versions of Exchange
# so, default Microsoft Exchange with OWA embeds version number inside HTML comments like:
# size=2><BR>Microsoft Exchange Server </FONT><FONT color=black size=2>Version 5.5 
#      SP4<BR><!-- 2653.23 -->Microsoft (R) Outlook (TM) Web Access <snip>
#
# go out on google and you'll see that most sites keep at least one of sigs[]
# or text[] 

sigs = make_array();
sigs['5.0'] = make_array('product', '5.0', 'version', '5.0.1457.0', 'sp', 0);
sigs['5.0 SP1'] = make_array('product', '5.0', 'version', '5.0.1458.0', 'sp', 1);
sigs['5.0 SP2'] = make_array('product', '5.0', 'version', '5.0.1460.13', 'sp', 2);
sigs['5.5'] = make_array('product', '5.5', 'version', '5.5.1960.4', 'sp', 0);
sigs['5.5 SP1'] = make_array('product', '5.5', 'version', '5.5.2232.5', 'sp', 1);
sigs['5.5 SP2'] = make_array('product', '5.5', 'version', '5.5.2448.4', 'sp', 2);
sigs['5.5 SP3'] = make_array('product', '5.5', 'version', '5.5.2650.24', 'sp', 3);
sigs['5.5 SP4'] = make_array('product', '5.5', 'version', '5.5.2653.23', 'sp', 4);
sigs['5.5 SP5'] = make_array('product', '5.5', 'version', '5.5.2658.10', 'sp', 5);
sigs['6.0'] = make_array('product', '2000', 'version', '6.0.4417.0', 'sp', 0);
sigs['6.0 SP1'] = make_array('product', '2000', 'version', '6.0.4712.0', 'sp', 1);
sigs['6.0 SP2'] = make_array('product', '2000', 'version', '6.0.5762.0', 'sp', 2);
sigs['6.0 SP3'] = make_array('product', '2000', 'version', '6.0.6249.0', 'sp', 3);
sigs['6.5'] = make_array('product', '2003', 'version', '6.5.6944.0', 'sp', 0);
sigs['6.5 SP1'] = make_array('product', '2003', 'version', '6.5.7226.0', 'sp', 1);
sigs['6.5 SP2'] = make_array('product', '2003', 'version', '6.5.7683.0', 'sp', 2);

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0, "The web server on port "+port+" does not support ASP");

res = http_send_recv3(method:"GET", port:port, item:"/owa/auth/logon.aspx", exit_on_fail:TRUE);
if ("X-OWA-Version" >< res[1])
{
  owaversion = strstr(res[1], "X-OWA-Version: ") - "X-OWA-Version: ";
  owaversion = owaversion - strstr(owaversion, '\n');
}
else
{
  # In case the X-OWA-Version header is missing
  if ("OwaPage = " >< res[2] && "<title>Outlook Web App" >< res[2])
  {
    chunk = strstr(res[2], 'link rel="shortcut icon" href="/owa/auth/') - 'link rel="shortcut icon" href="/owa/auth/';
    chunk = chunk - strstr(chunk, '>');
    owaversion = ereg_replace(string:chunk, pattern:'^[0-9\\.]+/.*', replace:"\1");
  }
}

if (!empty_or_null(owaversion))
{
  release = split(owaversion, sep:'.', keep:FALSE);
  release = release[0];

  if (!empty_or_null(exchange_vers[release]))
  {
    sp = 0;
    for (i=0; i < max_index(keys(exchange_vers[release]['sp'])); i++)
    {
      if (ver_compare(ver:owaversion, fix:exchange_vers[release]['sp'][i]) >= 0) sp = i;
      else break;
    }
    if (sp)
    {
      product = exchange_vers[release]['product'];
      if (int(release) >= 15) update_str = 'CU';
      else update_str = 'SP';
    }
  }
}
else
{
  cgi = "/exchange/logon.asp";

  w = http_send_recv3(method:"GET", port: port, item: cgi, follow_redirect: 1, exit_on_fail:TRUE);
  if (w[0] !~ "^HTTP/1\.[01] (200|403)") exit(0, "The host returned an unexpected response header.");
  r = strcat(w[0], w[1], '\r\n', w[2]);

  # permutations that I thought of
  # 200 OK -> sigmatch
  # 302 redirect -> 200 OK -> sigmatch
  # 403 Req SSL -> 200 OK -> sigmatch
  # 302 redirect -> 403 Req SSL -> 200 OK -> sigmatch

  if (w[0] =~ "HTTP/1\.[0-9] 403 Access Forbidden") exit(0, "Unable to access " + build_url(port:port, qs:cgi) + ".");
  # MA 2009-12-11: The old code force the test on port 443. I trashed that part.
  # 443 will be tested if the user scanned it.
 
  if ( (("L_strMailboxPlease_Message" >< r) || ("Outlook (TM) Web Access" >< r)) && "for Microsoft (R) Exchange Server" >< r )
  {
    # Narrow down the text
    chunk = strstr(r, "for Microsoft (R) Exchange Server") - "for Microsoft (R) Exchange Server";
    chunk = chunk - strstr(chunk, "Microsoft (R) Outlook (TM) Web Access");

    # Now extract the version number
    sig = strstr(chunk, "Version ") - "Version ";
    sig = sig - strstr(sig, "<");

    if (!empty_or_null(sigs[sig]))
    {
      product = sigs[sig]['product'];
      owaversion = sigs[sig]['version'];
      update_str = 'SP';
      sp = sigs[sig]['sp'];
    }
  }
}
if (owaversion)
{
  extra = make_array();
  extra_no_report = make_array();
  if (!empty_or_null(product))
    extra_no_report['RELEASE'] = product;
  if (!empty_or_null(sp))
    extra[update_str] = sp;

  register_install(
    app_name:'Outlook Web Access', 
    path:'', 
    version:owaversion, 
    extra:extra,
    extra_no_report:extra_no_report,
    port:port,
    cpe:'cpe:/a:microsoft:outlook_web_access',
    webapp:TRUE
  );
  report_installs(app_name:'Outlook Web Access', port:port);
}
else audit(AUDIT_NOT_DETECT, 'Outlook Web Access', port);
