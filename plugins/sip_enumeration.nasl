#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56983);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/01/07 21:38:30 $");

  script_name(english:"SIP Username Enumeration");
  script_summary(english:"Enumerates the users on the SIP server.");

  script_set_attribute(attribute:"synopsis", value:
"The SIP server on the remote host allows the enumeration of users.");
  script_set_attribute(attribute:"description", value:
"The SIP server on the remote host appears to respond differently to
registration requests for valid and invalid usernames.  Using that
fact, Nessus was able to enumerate some of the valid usernames.");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3261");
  script_set_attribute(attribute:"solution", value:
"Configure the SIP server to respond identically to valid and invalid
usernames.  This can be done in Asterisk, for example, by setting
'alwaysauthreject=yes' in sip.conf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");

  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("sip.inc");

function ext_exists(ext, port, proto)
{
  local_var sock, encaps, via_protocol, code, dst, i, matches, req, res, soc, src;

  soc = sip_open(port:port, proto:proto);
  if (!soc || isnull(soc)) return FALSE;

  via_protocol = proto;

  encaps = get_port_transport(port);
  if (!isnull(encaps) && proto == 'tcp')
  {
    if (encaps && encaps > ENCAPS_IP)
      via_protocol = 'tls';
  }

  if (!soc) return NULL;

  # Send the register request. We're using a register instead of an
  # invite because the former detected more extensions during testing.
  # Invites work depending on what context the extension is in, at
  # least on Asterisk. Invites persist, which will DoS the server
  # quickly due to too many open files.
  src = "sip:" + this_host() + ":" + get_source_port(soc);
  dst = "sip:" + ext + "@" + this_host() + ":" + port;
  req =
    'REGISTER ' + dst + ' SIP/2.0\r\n' +
    'To: <' + dst + '>\r\n' +
    'From: Nessus <' + src + '>;tag=' + generate_uuid() + '\r\n' +
    'Via: SIP/2.0/' + toupper(via_protocol) + ' ' + this_host() + '\r\n' +
    'Call-ID: ' + generate_uuid() + '\r\n' +
    'CSeq: ' + rand() + '\r\n' +
    'Content-Length: 0\r\n' +
    '\r\n';
  sip_send(socket:soc, data:req);
  code = NULL;
  for (i = 0; i < 5; i++)
  {
    # Receive the response.
    res = sip_recv(socket:soc);
    if (isnull(res))
      break;

    # Parse the status code from the response.
    matches = eregmatch(string:res["status"], pattern:"^SIP/2\.0 ([0-9]+) ");
    if (isnull(matches))
      break;

    code = int(matches[1]);
    if (code != 100)
      break;
  }

  close(soc);

  return code;
}

function enumerate_sip_extensions(port, proto)
{
  local_var reject, max, unauth, maybes, code, i, ext, report;

  # Decide which range of extensions to test.
  if (thorough_tests)
    max = 9999;
  else
    max = 999;

  reject = FALSE;
  unauth = make_list();
  maybes = make_list();

  # Enumerate extensions.
  for (i = 100; i <= max; i++)
  {
    code = ext_exists(ext:i, port:port, proto:proto);
    if (isnull(code))
      return FALSE;

    # A response of "200 OK" indicates that we have registered
    # successfully. This means that there is no authentication
    # required for this extension.
    if (code == 200)
      unauth = make_list(unauth, i);

    # A response of "401 Unauthorized" cannot be trusted on its own. SIP
    # servers can prevent enumeration by sending this status code for
    # registration attempts for both valid and invalid usernames. We can
    # only trust it if we get at least one "404 Not Found", at which
    # point we know that valid and invalid users are handled
    # differently.
    else if (code == 401)
      maybes = make_list(maybes, i);

    # A response of "404 Not Found" is the most reliable indicator we
    # can hope for that an extension is not valid.
    else if (code == 404)
      reject = TRUE;
  }

  if (max_index(unauth) == 0)
  {
    # If there are no unauthenticated extensions, and we couldn't find at
    # least one extension that was invalid, the SIP server is preventing
    # us from enumerating extensions.
    if (!reject)
      return FALSE;

    # If we've gotten 404s, but no 401s, we know that we haven't found
    # any extensions, and have confidence in that finding.
    if (max_index(maybes) == 0)
      return FALSE;
  }

  # Save the list of extensions that don't require authentication.
  foreach ext (unauth)
  {
    set_kb_item(name:"sip/ext/" + port, value:ext);
    set_kb_item(name:"sip/ext/unauth/" + port, value:ext);
  }

  # Save the list of extensions we found that require authentication,
  # but only if we're sure they exist.
  if (reject)
  {
    foreach ext (maybes)
    {
      set_kb_item(name:"sip/ext/" + port, value:ext);
      set_kb_item(name:"sip/ext/auth/" + port, value:ext);
    }
  }

  # Report our findings.
  if (report_verbosity > 0)
  {
    report = "";

    if (max_index(unauth) != 0)
    {
      report +=
        '\nThe remote SIP server has the following extensions that do not require authentication :' +
        '\n' +
        '\n  ' + join(unauth, sep:", ") +
        '\n';
    }

    if (reject)
    {
      report +=
        '\nThe remote SIP server has the following extensions that require authentication :' +
        '\n' +
        '\n  ' + join(maybes, sep:", ") +
        '\n';
    }
    security_warning(port:port, proto:proto, extra:report);
  }
  else security_warning(port:port, proto:proto);
  return TRUE;
}

udp_ports = get_kb_list("Services/udp/sip");
tcp_ports = get_kb_list("Services/sip");

is_vuln = FALSE;

# loop through TCP ports
if (!isnull(tcp_ports))
{
  foreach port (make_list(tcp_ports))
  {
    if (enumerate_sip_extensions(port:port, proto:"tcp")) is_vuln = TRUE;
  }
}

# loop through UDP ports
if (!isnull(udp_ports))
{
  foreach port (make_list(udp_ports))
  {
    if (enumerate_sip_extensions(port:port, proto:"udp")) is_vuln = TRUE;
  }
}

if (!is_vuln) exit(0, "Nessus was unable to enumerate extensions on any SIP service.");
else exit(0);
