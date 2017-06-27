#
# (C) Tenable Network Security, Inc.
#

# Thanks to Jason Haar for his help!


include("compat.inc");

if (description)
{
  script_id(51185);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/26 22:54:02 $");

  script_name(english:"Dell Integrated Remote Access Controller (iDRAC) Detection");
  script_summary(english:"Detects the iDRAC web server.");

  script_set_attribute(attribute:"synopsis", value:
"A remote management service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server has been fingerprinted as one embedded in Dell
Integrated Remote Access Controller (iDRAC), formerly known as Dell
Remote Access Controller (DRAC).");
  # http://www.dell.com/learn/us/en/555/solutions/integrated-dell-remote-access-controller-idrac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da64eb28");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# iDRAC is fragile, we do not want to miss it.
http_set_read_timeout(get_read_timeout() * 2);

http_set_gzip_enabled(TRUE);

port = get_http_port(default: 443, embedded: TRUE);

page = http_send_recv3(
  port   : port,
  method :'GET',
  item   : "/",
  follow_redirect : 2,
  exit_on_fail    : TRUE);

drac_detected = FALSE;
fw_ver = UNKNOWN_VER;
drac_version = UNKNOWN_VER;

# In some cases, Versions 5, 6, and 7 use a JavaScript redirect
# we will manually look for and handle the redirect
if (
  "function redirect()" >< page[2] ||
  '"javascript:redirect();"' >< page[2]
)
{
  link = NULL;
  # iDRAC 6/7 examples:
  # top.document.location.href= "/login.html";
  # top.document.location.href = "/index.html";
  match = egrep(
    pattern : 'top\\.document\\.location\\.href(\\s)?= "/(index|login)\\.html"',
    string  : page[2]
  );
  if (match) link = "/login.html";
  else if (!match)
  {
    match = eregmatch(
      pattern : 'top\\.document\\.location\\.replace\\("(.*)"\\)',
      string  : page[2]
    );
    if (!empty_or_null(match)) link = match[1];
  }

  if (link)
  {
    page = http_send_recv3(
     method : "GET",
     port   : port,
     item   : link,
     exit_on_fail : TRUE
    );
  }
}

# Check if it looks like DRAC 4
if ("<title>Remote Access Controller</title>" >< page[2])
{
  drac_detected = TRUE;
  ver = eregmatch(
    pattern : 'var s_oemProductName = "DRAC ([0-9]+)"',
    string  : page[2]
  );
  if (!empty_or_null(ver)) drac_version = ver[1];
  else drac_version = "4 or earlier";

  # Grab version from /cgi/about page
  res = http_send_recv3(
    method  : "GET",
    item    : "/cgi/about",
    port    : port,
    exit_on_fail : TRUE
  );
  build = eregmatch(
    pattern : 'var s_build = "([0-9\\.]+) \\(Build .*',
    string  : res[2]
  );
  if (!empty_or_null(build)) fw_ver = build[1];
}

# DRAC 5
# Check for response expected to be seen on /cgi-bin/webcgi/index
if (
  egrep(pattern:'\\<IpAddress\\>([0-9\\.]+)\\</IpAddress\\>', string:page[2], icase:TRUE) &&
  ("<drac>" >< page[2]) && ("</drac>" >< page[2])
)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/cgi/lang/en/login.xsl",
    exit_on_fail : TRUE
  );
  if ("Dell Remote Access Controller" >< res[2])
  {
    drac_detected = TRUE;

    ver = eregmatch(
      pattern : 'strProductName"\\>DRAC ([0-9]+)\\<',
      string  : res[2]
    );
    if (!empty_or_null(ver)) drac_version = ver[1];
    else drac_version = "5 or earlier";

    # Get DRAC version from /cgi-bin/webcgi/about
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/cgi-bin/webcgi/about",
      exit_on_fail : TRUE
    );

    if ("<drac>" >< res2[2])
    {
      build = eregmatch(
        pattern :"<FirmwareVersion>([0-9\.]+)</FirmwareVersion>",
        string  : res2[2]
      );
      if (!empty_or_null(build)) fw_ver = build[1];
    }
  }
}

# DRAC 6 / 7
pat = "<title>(Integrated)?((\s)?Dell)? Remote Access Controller [0-9]+";

if (
  egrep(pattern:pat, string:page[2], icase:TRUE) ||
  page[2] =~ 'eLang.getString\\("STR_DEFAULT_DOMAIN"\\)\\s*\\+\\s*"iDRAC[67]"'
)
{
  drac_detected = TRUE;
  # grab the version from /public/about.html
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/public/about.html",
    exit_on_fail : TRUE
  );

  if(!res[2] || "Remote Access Controller" >!< res[2])
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/Applications/dellUI/Strings/EN_about_hlp.htm",
      exit_on_fail : TRUE
    );
  }

  if (res[2] =~ "Remote Access Controller [0-9]+")
  {
    ver = eregmatch(pattern:"Remote Access Controller ([0-9]+)",string:res[2]);
    if (!empty_or_null(ver)) drac_version = ver[1];
    else drac_version = "6, 7 or later";

    ver = eregmatch(
      pattern : 'var fwVer = "([0-9.]+)(\\(Build [0-9]+\\))?"',
      string  : res[2]
    );

    if (empty_or_null(ver))
      ver = eregmatch(pattern:"Version\s*([0-9.]+)[\s\n]*<", string:res[2]);

    if (!empty_or_null(ver)) fw_ver = ver[1];
    if (!empty_or_null(ver[2])) fw_ver = ver[1] + "." + ver[2];

  }
}

# DRAC 8 and newer versions require ajax to display version info on about page
if("/session?aimGetProp=fwVersionFull" >< page[2] ||
   page[2] =~ "gen_iDrac[\d+]")
{
  drac_detected = TRUE;

  # multiple versions may be present on a page
  # we need to parse the page for the highest
  # DRAC version
  if ("gen_iDrac6" >< page[2]) ver = "6";
  if ("gen_iDrac7" >< page[2]) ver = "7";
  if ("gen_iDrac8" >< page[2]) ver = "8";
  if (!empty_or_null(ver)) drac_version = ver;

  # request/parse firmware version
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/session?aimGetProp=fwVersionFull",
    exit_on_fail : TRUE
  );

  # parse the build version and append to Firmware Version
  #
  # DRAC 8 Example:
  #   fwVersionFull" :"2.30.30.30 (Build 50)
  ver = eregmatch(pattern:'fwVersionFull.+?([0-9.]+)(\\s*\\(Build\\s([0-9]+))?',
                  string:res[2]);

  if (!empty_or_null(ver)) fw_ver = ver[1];
  if (!empty_or_null(ver)) fw_build = ver[3];
  if ((!empty_or_null(fw_ver)) || (!empty_or_null(fw_build)))
    fw_ver = fw_ver + "." + fw_build;
}

# DRAC/MC (Dell Remote Access Controller/Modular Chassis)
pat = "Dell\(TM\) Remote Access Controller/Modular Chassis\</title\>";
if (egrep(pattern:pat, string:page[2], icase:TRUE))
{
  drac_detected = TRUE;

  # Grab Version from /about.html
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/about.htm",
    exit_on_fail : TRUE
  );

  if (egrep(pattern:pat, string:res[2], icase:TRUE))
  {
    drac_version = "DRAC/MC";
    ver = eregmatch(
      pattern : "Version .* &nbsp;([0-9\.]+) \(Build .*\)\<",
      string  : res[2]
    );
    if (!empty_or_null(ver)) fw_ver = ver[1];
  }
}


# DRAC is detected on 443, but NAT or RP may be in place
if (port != 80)
{
  # Play on the safe side: disable port 80 too.
  p = 80;
  b = http_get_cache(port: p, item: '/');
  if ( 'HTTP/1.1 301 ' >< b &&
       egrep(string: b, pattern: '^Location: *https://.*/start.html') )
  {
    declare_broken_web_server(port:p, reason:'iDRAC web interface is fragile.');
  }
}

if (drac_detected)
{
  set_kb_item(name: 'Services/www/' + port + '/embedded', value: TRUE);

  register_install(
    port     : port,
    app_name : 'iDRAC',
    path     : "/",
    version  : drac_version,
    extra    : make_array('Firmware Version', fw_ver),
    webapp   : TRUE);

  report_installs(app_name:'iDRAC', port:port);
}
else audit(AUDIT_WEB_APP_NOT_INST, 'iDRAC', port);
