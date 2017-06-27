#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15616);
  script_version("$Revision: 1.17 $"); 
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2002-0181");
  script_bugtraq_id(4444);
  script_osvdb_id(5345);

  script_name(english:"Horde IMP status.php3 script Parameter XSS");
  script_summary(english:"Checks for status.php3 XSS flaw in Horde IMP");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of Horde IMP in which
the 'status.php3' script is vulnerable to a cross-site scripting attack 
since information passed to it is not properly sanitized.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/98");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IMP version 2.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:imp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses : XSS");
  
  script_dependencie("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    url = string(
      dir, 
      # nb: if you change the URL, you probably need to change the 
      #     pattern in the egrep() below.
      "/status.php3?script=<script>foo</script>"
    );
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);
           
    if (egrep(string:res, pattern:'<script>foo</script>')) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
