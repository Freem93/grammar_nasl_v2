#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10165);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2012/12/10 14:56:53 $");

 script_cve_id("CVE-1999-0045");
 script_bugtraq_id(686);
 script_osvdb_id(128);
 script_xref(name:"CERT-CC", value:"CA-1997-07");
 
 script_name(english:"NCDSA HTTPd nph-test-cgi Arbitrary Directory Listing");
 script_summary(english:"Tries to get a directory listing with nph-test-cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
information disclosure vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains the 'nph-test-cgi' test script, which
is included by default with some web servers. 

The version of this script on the remote host fails to quote input to
several environment variables, such as 'QUERY_STRING', before echoing
it back as part of a shell script.  An unauthenticated attacker can
leverage this issue to list the contents of directories on the remote
host, subject to the permissions of the web server user id.");
 script_set_attribute(attribute:"solution", value:"Disable or delete the CGI script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/02/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

cgi = "nph-test-cgi";
pat = string("[= ]", cgi, "($| )");


foreach dir (cgi_dirs())
{
  url = string(dir, "/", cgi);

  # Try an exploit using QUERY_STRING.
  info = "";

  w = http_send_recv3(method:"GET", item: url+"?*", version: 10, port: port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);
  lines = egrep(pattern:"^QUERY_STRING *= *", string:res);
  if (lines)
  {
    foreach line (split(lines, keep:FALSE))
    {
      # There's a problem if we see the script name in the line; eg,
      #   QUERY_STRING = nph-test-cgi printenv test-cgi
      if (ereg(string:line, pattern:pat))
      {
        info = line;
        break;
      }
    }
  }

  # If the exploit didn't work but the script appears to exist...
  if (lines && !info && thorough_tests)
  {
    # Try an exploit using SERVER_PROTOCOL.
    w = http_send_recv3(method:"GET", item: url+"?x", version: 10, port: port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);

    lines = egrep(pattern:"^SERVER_PROTOCOL *= *", string:res);
    if (lines)
    {
      foreach line (split(lines, keep:FALSE))
      {
        # There's a problem if we see the script name in the line; eg,
        #   SERVER_PROTOCOL = HTTP/1.0 nph-test-cgi printenv test-cgi
        if (ereg(string:line, pattern:pat))
        {
          info = line;
          break;
        }
      }
    }
  }

  if (info)
  {
    if (report_verbosity)
    {
      info = strstr(info, "=") - "=";
      while (info[0] == " ") info = substr(info, 1);
      if ("HTTP/" >< info) info = ereg_replace(pattern:"^HTTP/[0-9]\.[0-9] +", replace:"", string:info);
      info = str_replace(find:" ", replace:'\n  ', string:info);
      exploit = http_last_sent_request();
      report = string(
        "\n",
        "Here are the contents of the CGI directory '", dir, "' on the\n",
        "remote host :\n",
        "\n",
        "  ", info, "\n",
        "\n",
        "which Nessus collected by sending the following request :\n",
        "\n",
        "  ", exploit, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
