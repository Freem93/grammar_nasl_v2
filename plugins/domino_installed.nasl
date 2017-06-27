#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27855);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/01/22 20:35:42 $");

  script_name(english:"IBM Domino Detection (uncredentialed check)");
  script_summary(english:"Checks for IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"IBM Domino is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM Domino (formerly IBM Lotus Domino), an enterprise application for
collaborative messaging, scheduling, directory services, and web
services, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/ibmdomino");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "ldap_search.nasl", "http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, "Services/ldap", 389, "Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("http.inc");
include("webapp_func.inc");

# Try to get the version number from a banner.
ver = NULL;
service = NULL;

# - SMTP.
if (isnull(ver))
{
  port = get_kb_item("Services/smtp");
  if (!port) port = 25;
  if (get_port_state(port))
  {
    banner = get_smtp_banner(port:port);
    if (
      banner &&
      (
        " Service (Lotus Domino Release " >< banner ||
        " Lotus Domino Release " >< banner ||
        " Service (IBM Domino Release " >< banner ||
        " IBM Domino Release " >< banner
      )
    )
    {
      pat = " (Service \()?(Lotus|IBM) Domino Release ([0-9]([a-zA-Z0-9.]+)?( HF\d+)?)";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            service = "SMTP";
            ver = item[3];
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0, "No version could be obtained from the SMTP service on port "+port+" and the 'Perform thorough tests' setting is not enabled.");
  }
}
# - POP3
if (isnull(ver))
{
  port = get_kb_item("Services/pop3");
  if (!port) port = 110;
  if (get_port_state(port))
  {
    banner = get_pop3_banner(port:port);
    if (
      banner &&
      (
        " Lotus Notes POP3 " >< banner ||
        " IBM Notes POP3 " >< banner
      )
    )
    {
      pat = " (Lotus|IBM) Notes POP3 server version Release ([0-9][^ ]+( HF[0-9.]+)?) ready";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[2];
            service = "POP3";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0, "No version could be obtained from the POP3 service on port "+port+" and the 'Perform thorough tests' setting is not enabled.");
  }
}
# - IMAP.
if (isnull(ver))
{
  port = get_kb_item("Services/imap");
  if (!port) port = 143;
  if (get_port_state(port))
  {
    banner = get_imap_banner(port:port);
    if (banner && " Domino IMAP4 " >< banner)
    {
      pat = " Domino IMAP4 Server Release ([0-9][^ ]+( HF[0-9.]+)?) ready";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            service = "IMAP";
            break;
          }
        }
      }
    }
    if (isnull(ver) && !thorough_tests) exit(0, "No version could be obtained from the IMAP service on port "+port+" and the 'Perform thorough tests' setting is not enabled.");
  }
}
# - LDAP.
if (isnull(ver))
{
  port = get_kb_item("Services/ldap");
  if (!port) port = 389;
  if (get_port_state(port))
  {
    vendorname = get_kb_item("LDAP/"+port+"/vendorName");
    vendorversion = get_kb_item("LDAP/"+port+"/vendorVersion");
    if (
      vendorname && "IBM Lotus" >< vendorname &&
      vendorversion && "Release " >< vendorversion
    )
    {
      service = "LDAP";
      ver = strstr(vendorversion, "Release ") - "Release ";
    }
  }
  if (isnull(ver) && !thorough_tests) exit(0, "No version could be obtained from the LDAP service on port "+port+" and the 'Perform thorough tests' setting is not enabled.");
}
# - HTTP
found = FALSE;
if (isnull(ver))
{
  port = get_http_port(default:80);
  if (!port) port = 80;
  server_name = get_kb_item("www/real_banner/"+port);
  if (!isnull(server_name))
  {
    server_name = chomp(server_name);
    if (server_name)
    {
      if ("Domino" >< server_name)
      {
        matches = eregmatch(string:server_name, pattern:"^Server: (IBM|Lotus)-Domino/(([0-9\.]+)($|FP[0-9]+( HF\d+)?))");

        if (!isnull(matches))
        {
          service = "HTTP";
          ver = matches[1];
          set_kb_item(name:"www/Domino/"+port+"/version", value:ver);
        }
      }
    }
  }
  else
  {
    server_name = get_kb_item("www/banner/"+port);
    if(!isnull(server_name))
    {
      if ("Domino" >< server_name)
      {
	service = "HTTP";
        found = TRUE;
      }
    }
  }
  if (isnull(ver) && !thorough_tests) exit(0, "No version could be obtained from the HTTP service on port "+port+" and the 'Perform thorough tests' setting is not enabled.");
}

# Issue a report if it was found on the remote.
if ( (!isnull(ver) && !isnull(service)) || found)
{
  if ("FP" >< ver) ver = str_replace(find:"FP", replace:" FP", string:ver);
  else if (found) ver = UNKNOWN_VER;

  set_kb_item(name:"Domino/Version", value:ver);
  set_kb_item(name:"Domino/Version_provided_by_port", value:port);

  if (service == "LDAP")
    note =
      'Based on the response to an LDAP request, IBM Domino version '+ver+'\n'+
      'appears to be running on the remote host.\n';
  else
  {
    if (ver == UNKNOWN_VER) report_ver = "";
    else report_ver = " version " +ver;
    note =
      'According to its '+service+' banner, IBM Domino'+report_ver+' appears\n'+
      'to be running on the remote host.\n';
  }
  security_note(port:0, extra: note);
}
else audit(AUDIT_NOT_INST, "IBM Domino");
