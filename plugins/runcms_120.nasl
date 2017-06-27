#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19504);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2691", "CVE-2005-2692");
  script_bugtraq_id(14631, 14634);
  script_osvdb_id(18907, 18908, 18909, 18910, 18911, 18912);

  name["english"] = "RunCMS <= 1.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The version of RunCMS installed on the remote host allows attackers to
overwrite arbitrary variables by passing them via a POST method and
may also suffer from several SQL injection vulnerabilities resulting
in, for example, disclosure of the admin password hash." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00094-08192005" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor - the flaws reportedly were silently patched in
mid-July 2005." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/19");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in RunCMS <= 1.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check whether we're dealing with RunCMS / E-Xoops.
  r = http_send_recv3(method:"GET",item:string(dir, "/user.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  pat = "RUNCMS\.? *(.+) +&copy; 20[0-9][0-9] RUNCMS";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = chomp(ver[1]);
        break;
      }
    }

    # Try to exploit the variable-overwriting flaw to change the start page.
    #
    # nb: this only works if register_globals is off.
    postdata = string("xoopsConfig[startpage]=", SCRIPT_NAME);
    r = http_send_recv3(method: "POST", item: dir+"/", port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if we see a redirect involving our script name.
    if (string("Location: modules/", SCRIPT_NAME) >< r[1]) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }

    # Fall back to testing the version number then.
    if (ver && ver =~ "^(0\..*|1\.(0.*|1A?|2))$") {
      report = string(
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of RunCMS\n",
        "installed there.\n"
      );
      security_hole(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
