# --------------------------------------------------------------
# (c) Recx Ltd 2009-2012
# http://www.recx.co.uk/
#
# Detect Oracle Application Express Version on Apex/HTTP ports
# Version 1.0
# --------------------------------------------------------------

include("compat.inc");

if (description)
{
  script_id(64705);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/22 19:46:31 $");

  script_name(english:"Oracle Application Express (Apex) Version Detection");
  script_summary(english:"Checks for Oracle Apex Version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a version Oracle Apex.");
  script_set_attribute(attribute:"description", value:"The remote host is running Oracle Application Express (Apex).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/developer-tools/apex/index.html");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Recx Ltd.");

  script_dependencies("http_version.nasl", "oracle_apex_detect.nasl");
  script_require_keys("Oracle/Apex");
  script_require_ports("Services/www", 8080, 80, 443);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

v = make_array();

# Apex versions and release date;
v["2.2"] = "July 27, 2006";
v["2.2.1"] = "September 14, 2006";
v["3.0"] = "March 16, 2007";
v["3.0.1"] = "June 29, 2007";
v["3.1"] = "February 29, 2008";
v["3.1.1"] = "May 22, 2008";
v["3.1.2"] = "August 28, 2008";
v["3.2"] = "August 25, 2009";
v["3.2.1"] = "January, 2010";
v["4.0"] = "23 June, 2010";
v["4.0.1"] = "18 August, 2010";
v["4.0.2"] = "19 November, 2010";
v["4.1"] = "24 August, 2011";
v["4.1.1"] = "21 February, 2012";
v["4.2"] = "12 October, 2012";

function raise_finding(port, location, version)
{
  local_var report, date;
  if(report_verbosity > 0)
  {
    report = '\n  URL          : ' + build_url(port:port, qs:location) +
             '\n  Version      : ' + version;
    date = v[version];
    if (date)
      report += '\n  Release Date : ' + date;
    report += '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

function raise_unknown(port)
{
  local_var report;
  if(report_verbosity > 0)
  {
    report = '\nThe Oracle Application Express (Apex) version could not be determined on port ' + port + '.\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

port = get_http_port(default:8080);

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

# Grab the Apex port and exit if not available
if (!get_kb_item("Oracle/Apex/" + port))
  exit(0, "The 'Oracle/Apex/" + port + "' KB item is not set.");

location = get_kb_item("Oracle/Apex/"+port+"/Location");
if(!location)
  exit(0, "The 'Oracle/Apex/" + port + "/Location' KB item is not set.");

# Grab the Apex IMAGE_PREFIX and exit if not available
imagePrefix = get_kb_item("Oracle/Apex/" + port + "/ImagePrefix");
if(!imagePrefix)
  exit(0, "The 'Oracle/Apex/" + port + "/ImagePrefix' KB item is not set.");

pattern = make_array();
url = make_array();

# Define Oracle Apex version specific patterns.
pattern[0] = "Application Express Version:  ";
pattern[1] = '<meta name="partnum" content="';

# Define Oracle Apex specific request URLs that trigger known responses.
url[0] = "/" + imagePrefix + "/apex_version.txt";
url[1] = "/" + imagePrefix + "/doc/index.htm";

flag = 0;
for(i=0;url[i];i=i+1)
{
  req = http_get(item:url[i], port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if ( buf == NULL )
    exit(1, "Unable to establish connection to server on port " + port + ".");

  # Apex version >= 4.0
  if (pattern[0] >< buf)
  {
    flag = 1;
    arrVersion = eregmatch(pattern:"Application Express Version:\s*([\d.]*)",string:buf);
    raise_finding(port:port, location:location, version:arrVersion[1]);
    set_kb_item(name:"Oracle/Apex/" + port + "/Version", value:arrVersion[1]);
    break;
  }

  # Apex version 2.2 - 3.2.1
  if (pattern[1] >< buf)
  {
    flag = 1;
    arrVersion = eregmatch(pattern:pattern[1] + "([EB][0-9]*\-0[12])",string:buf); # ,match <meta name="partnum" content="E11947-01" />
    if (arrVersion[1] == "B28550-01")
    {
      # Could be Apex 2.2 or 2.2.1
      request = "/" + imagePrefix + "/javascript/htmldb_html_elements.js";
      req = http_get(item:request, port:port);
      buf = http_keepalive_send_recv(port:port, data:req);
      if ( buf == NULL )
        exit(1, "Unable to establish connection to server on port " + port + ".");

      # New functions added in Apex 2.2.1 ie_RowFixStart and ie_RowFixFinish
      if ("ie_RowFixStart" >< buf)
        version = "2.2.1";
      else
        version = "2.2";
    }
    else if (arrVersion[1] == "B32471-01")
    {
      # Could be Apex 3.0 or 3.0.1
      request = "/" + imagePrefix + "/css/core_V22.css";
      req = http_get(item:request, port:port);
      buf = http_keepalive_send_recv(port:port, data:req);
      if ( buf == NULL )
        exit(1, "Unable to establish connection to server on port " + port + ".");

      # There was a typo in Apex 3.0
      if ("margion" >< buf)
        version = "3.0";
      else
        version = "3.0.1";
    }
    else if (arrVersion[1] == "E10499-01")
    {
      # Could be Apex 3.1 or 3.1.1
      request = "/" + imagePrefix + "/css/uncompressed/apex_3_1.css";
      req = http_get(item:request, port:port);
      buf = http_keepalive_send_recv(port:port, data:req);
      if ( buf == NULL )
        exit(1, "Unable to establish connection to server on port " + port + ".");

      # The display:block was removed in Apex 3.1.1
      if ("fieldset{border:0;margin:0;padding:0;display:block;}" >< buf)
        version = "3.1";
      else
        version = "3.1.1";
    }
    else if (arrVersion[1] == "E10499-02")
    {
      version = "3.1.2";
    }
    else if (arrVersion[1] == "E11838-01")
    {
      version = "3.2";
    }
    else if (arrVersion[1] == "E11947-01")
    {
      version = "3.2.1";
    }
    else
    {
      # Version unknown or unable to be establised.
      version = "Unknown";
      raise_unknown(port:port);
      set_kb_item(name:"Oracle/Apex/"+port+"/Version",value:version);
      break;
    }

    # Raise finding
    raise_finding(port:port, location:location, version:version);
    set_kb_item(name:"Oracle/Apex/" + port + "/Version",value:version);
    break;
  }
}

if(!flag)
  exit(0, "Unable to determine version of Oracle Apex server listening on port " + port + ".");
