#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34110);
  script_version("$Revision: 1.12 $");

  script_bugtraq_id(30857);
  script_osvdb_id(50418, 50419);
  script_xref(name:"EDB-ID", value:"6311");

  script_name(english:"Simple PHP Blog config/users.php Arbitrary User Password Hash Disclosure");
  script_summary(english:"Retrieves user list");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Simple PHP Blog installed on the remote host allows an
unauthenticated, remote attacker to retrieve information about
non-admin users defined to the application, including their user names
and password hashes, which could in turn be used to gain access to the
application. 

While these users do not have administrative access to the
application, they may have the ability to moderate comments, delete
blog entries, or edit entries.  They may also have the ability to
execute arbitrary code by leveraging a vulnerability involving
uploading of 'emoticons', although Nessus has not tested this issue." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/08");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("sphpblog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sphpblog");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/config/users.php");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];
  # Parse out info about users.
  ok = TRUE;
  lines = split(res, keep:FALSE);
  foreach line (split(res, keep:FALSE))
  {
    fields = split(line, sep:"|", keep:FALSE);
    if (max_index(fields) != 9)
    {
      ok = FALSE;
      break;
    }
  }

  # There's a problem if all lines look like users.
  if (ok)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to obtain the list of users defined to Simple PHP\n",
        "Blog (except for the administrator) using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here is the list :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:res)
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
