#
# (C) Tenable Network Security, Inc.
#

# Modifications by Daniel Reich <me at danielreich dot com>
#
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the
#   order of Copyright and &copy;
# - Revision 1.2
#
# The above changes have since been removed.
# "HP Remote Insight ILO Edition II" mentioned above is a misspelling of
# "Remote Insight Light-Out Edition II" which is NOT iLO and is irrelevant.

include("compat.inc");

if (description)
{
  script_id(20285);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/03/07 14:15:29 $");

  script_name(english:"HP Integrated Lights-Out (iLO) Detection");
  script_summary(english:"Detects iLO");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an HP Integrated Lights-Out (iLO) server.");
  script_set_attribute(attribute:"description", value:
"The remote host is an HP Integrated Lights-Out (iLO) server. These
servers are embedded systems integrated into HP ProLiant servers for
the purpose of out-of-band management.");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this host if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_require_ports("Services/www", 80, 443);
  script_dependencies("httpver.nasl", "broken_web_server.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("json.inc");
include("misc_func.inc");
include("obj.inc");
include("path.inc");
include("webapp_func.inc");

##
# Extract the contents of the given xml tag without attributes.
#
# @anonparam tag The tag to search for.
# @anonparam xml The xml to search.
#
# @return the value between <tag> and </tag>.
##
function xml_match()
{
  local_var tag, xml;
  tag = _FCT_ANON_ARGS[0];
  xml = _FCT_ANON_ARGS[1];

  xml = str_replace(string:xml, find:'\n', replace:"");

  local_var m;
  m = eregmatch(
    string  : xml,
    pattern : "<" + tag + ">(.*?)</" + tag + ">"
  );

  if (isnull(m))
    return NULL;

  return m[1];
}

##
# Parse the value of the <PN> tag from xmldata?item=all
#
# @param pn The value of the <PN> tag.
#
# @Numeric generation.
##
function parse_pn_element()
{
  local_var pn;
  pn = _FCT_ANON_ARGS[0];

  if (pn == "Integrated Lights-Out (iLO)")
    return 1;

  local_var m;
  m = eregmatch(
    string  : pn,
    pattern : "^Integrated Lights-Out (\d+)"
  );

  if (isnull(m))
    return NULL;

  return int(m[1]);
}

##
# Parse the response from xmldata?item=all
#
# @param xml The xml string to parse.
#
# @return A hash with data from xmldata?item=all if enabled, or an empty
#  hash if iLO is detected but this feature (Insight Management integration)
#  is not.
##
function parse_xmldata_all()
{
  local_var xml;
  xml = _FCT_ANON_ARGS[0];
  xml = str_replace(string:xml, find:'\n', replace:"");

  # Host is iLO, but xmldata is disabled.
  if (xml =~ "<RIMP>\s*</RIMP>")
    return make_array();

  if (xml !~ "<PN>Integrated Lights-Out .*?</PN>")
    return NULL;

  # We will populate this with data from the XML file.
  local_var info;
  info = make_array();


  # The PN element contains the full iLO name, including generation.
  local_var pn_element;
  pn_element = xml_match("PN", xml);

  # Attempt to parse PN element, and if successful store generation in info.
  local_var generation;
  generation = NULL;
  if (!isnull(pn_element))
    generation = parse_pn_element(pn_element);
  if (!isnull(generation))
    info["generation"] = generation;

  # Retrieve and store the firmware version.
  local_var firmware;
  firmware = xml_match("FWRI", xml);
  if (!isnull(firmware))
    info["firmware"] = firmware;

  # Retrieve and store the model of the ProLiant server.
  local_var server_model;
  server_model = xml_match("SPN", xml);
  if (!isnull(server_model))
    info["server_model"] = server_model;

  # Retrieve and store Single Sign-On status. Unavailable in iLO1.
  local_var sso;
  sso = xml_match("SSO", xml);
  if (!isnull(sso))
    info["sso"] = sso == "1";

  return info;
}

##
# /xmldata?item=All is (if not disabled) available for all iLO generations
# and across http and https. Contains all data able to be collected.
# Here we request it from the supplied port and parse its results.
#
# @anonparam port The port to make requests to.
#
# @return NULL if unsuccessful, data from parse_xmldata_all otherwise.
##
function detect_xmldata_all()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/xmldata?item=All"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  return parse_xmldata_all(res[2]);
}

##
# Detect iLO over https, which behaves differently than http.
# Over https, we will reach the login page when we request / and
# requests to /json/login_session will not lead to a redirect.
#
# We start by requesting the login page at /. If iLO3-4, we go on
# to request /json/login_session which will give us the firmware version.
#
# @anonparam port The port to make requests to.
#
# @return make_array(generation) if iLO1-2, "version" as well if
#   iLO3-4 and it can be derived. Return NULL if iLO is not detected.
##
function detect_https()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  # Over https, this will retrieve the login page.
  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  local_var m;
  m = egrep(pattern:"Hewlett-Packard (Development )?Company", string:res[2], icase:TRUE);
  if (!m)
    return NULL;

  local_var info;
  info = make_array();

  if (
    ("<TITLE>HP Integrated Lights-Out Login</TITLE>" >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out </span>' >< res[2])
  )
  {
    info["generation"] = 1;
  }
  else if (
    ("<TITLE>HP Integrated Lights-Out 2 Login</TITLE>" >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out 2 </span>' >< res[2])
  )
  {
    if ("sso=1;" >< res[2])
      info["sso"] = TRUE;
    else if ("sso=0;" >< res[2])
      info["sso"] = FALSE;

    info["generation"] = 2;
  }
  else if ("<title>iLO 3</title>" >< res[2] || 'id="titleHeading">Integrated&nbsp;Lights-Out&nbsp;3</h1>' >< res[2])
  {
    info["generation"] = 3;
  }
  else if ("<title>iLO 4</title>" >< res[2] || 'id="titleHeading">iLO&nbsp;4</h1>' >< res[2])
  {
    info["generation"] = 4;
  }
  else
  {
    return NULL;
  }

  # iLO1-2 do not have /json/login_session
  if (info["generation"] < 3)
    return info;

  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/json/login_session"
  );

  if (isnull(res) || isnull(res[2]))
    return info;

  local_var json;
  json = json_read(res[2]);

  if (isnull(json) || isnull(json[0]) || isnull(json[0]["version"]))
    return info;

  info["firmware"] = json[0]["version"];

  return info;
}

##
# This function detects iLO1-2 over HTTP.
#
# In iLO1-2, HTTP / leads to a redirect portal. We parse it to
# learn the generation of iLO.
#
# @anonparam port The port to make the request to.
#
# @return make_array(generation). "sso" may be present if iLO2.
#   Returns NULL if iLO1-2 is not detected.
##
function detect_http()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var res;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/"
  );

  if (isnull(res) || isnull(res[2]))
    return NULL;

  local_var headers;
  headers = parse_http_headers(status_line:res[0], headers:res[1]);

  # iLO3-4 will return an http redirect.
  if (headers["$code"] != 200)
    return NULL;

  local_var info;
  info = make_array();

  # At this point, if this is iLO, we are at the redirect portal for iLO1 or iLO2.
  if (
     ('document.title="Integrated Lights Out 2: "' >< res[2]) ||
     ('class="loginTitle">Integrated Lights-Out 2 </span>' >< res[2])
  )
  {
    info["generation"] = 2;
  }
  else if (
    ('document.title="Integrated Lights Out: "' >< res[2]) ||
    ('class="loginTitle">Integrated Lights-Out </span>' >< res[2])
  )
  {
    info["generation"] = 1;
  }
  else
    return NULL;

  return info;
}

##
# Is the transport for the given port SSL?
#
# @anonparam port Port to lookup.
#
# @return TRUE if SSL, FALSE if not or unknown.
##
function is_ssl()
{
  local_var port;
  port = _FCT_ANON_ARGS[0];

  local_var encaps;
  encaps = get_kb_item("Transports/TCP/" + port);

  return  (!isnull(encaps) && encaps > ENCAPS_IP);
}

##
# Merges hashes.
#
# @param primary_hash The hash to merge hashes into.
# @param hash1, hash2, etc. The hashes to merge into the primary_hash.
#
# @return If all hashes are NULL, returns NULL, otherwise the merger of
#   all hashes. If an argument is NULL, it is ignored.
##
function merge_hashes()
{
  local_var primary_hash;
  primary_hash = NULL;

  local_var hash;
  foreach hash (_FCT_ANON_ARGS)
  {
    if (isnull(hash))
      continue;

    if (isnull(primary_hash))
      primary_hash = make_array();

    local_var key;
    foreach key (keys(hash))
    {
      if (!isnull(hash[key]))
        primary_hash[key] = hash[key];
    }
  }

  return primary_hash;
}

# Unfirewalled, there should be exactly 1 http port and 1 https port.
# We retrieve a list and not branch because we are detecting whether or
# not the host server is iLO, not which ports are running the web interface.
ports = get_kb_list("Services/www");

# By default, iLO listens on 80 and 443.
ports = add_port_in_list(list:ports, port:80);
ports = add_port_in_list(list:ports, port:443);

# Will track ports the interface is listening on.
# We may not have the firmware version until all ports are tried,
# so we delay calls to add_install.
interface_ports = make_list();

info = NULL;
foreach port (ports)
{
  # If enabled, xmldata?item=all contains a superset of the data we could
  # retrieve by other means, so we try it first.
  xml_info = detect_xmldata_all(port);

  # Not null signifies either that we were able to retrieve data or that
  # the remote host is iLO and the feature is disabled.
  if (!isnull(xml_info))
    info = merge_hashes(info, xml_info);

  more_info = NULL;
  if (isnull(xml_info) || isnull(info["generation"]))
  {
    if (is_ssl(port))
      more_info = detect_https(port);
    else
      more_info = detect_http(port);

    info = merge_hashes(info, more_info);
  }

  if (!isnull(more_info) || !isnull(xml_info))
    interface_ports = make_list(interface_ports, port);
}

if (isnull(info))
  audit(AUDIT_NOT_DETECT, "HP Integrated Lights-Out");

# Now that we have exhaustively attempted to find the firmware
# we record the existence of the web interface.
foreach port (interface_ports)
{
  replace_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  # There can only be one version and instance of the web app, though
  # it may listen on multiple ports (max 1 http and 1 https). All settings
  # are the same across those ports.
  add_install(
    appname : "ilo",
    dir     : "/",
    port    : port,
    ver     : info["firmware"]
  );

  if (info["sso"])
    set_kb_item(name:"www/ilo/" + port + "/sso_enabled", value:info["sso"]);
}

# This information is about the host's firmware.
# Nothing is specific to the web interface.
foreach key (make_list("generation", "firmware"))
{
  if (isnull(info[key]))
    continue;

  set_kb_item(name:"ilo/" + key, value:info[key]);
}

report = NULL;
if (report_verbosity && max_index(keys(info)) > 0)
{
  report = '\nHP Integrated Lights-Out (iLO)\n';

  if (!isnull(info["generation"]))
    report += '\n  Generation       : ' + info["generation"];

  if (!isnull(info["firmware"]))
    report += '\n  Firmware Version : ' + info["firmware"];

  if (!isnull(info["sso"]))
  {
    if (info["sso"])
      report += '\n  Single Sign-On   : Enabled';
    else
      report += '\n  Single Sign-On   : Disabled';
  }

  if (!isnull(info["server_model"]))
  {
    report += '\n\nAssociated ProLiant Server\n';
    report += '\n  Model : ' + info["server_model"];
  }

  report += '\n';
}

security_note(port:0, extra:report);
