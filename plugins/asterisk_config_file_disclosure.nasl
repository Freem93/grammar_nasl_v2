#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21303);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2006-2020");
  script_osvdb_id(24805);

  script_name(english:"Asterisk Recording Interface (ARI) includes/main.conf Remote Credential Disclosure");
  script_summary(english:"Tries to read ARI's configuration file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Asterisk Recording Interface (ARI), a
web-based portal for the Asterisk PBX software. 

The version of ARI installed on the remote host allows an
unauthenticated attacker to view its configuration file, which
contains sensitive information such as passwords." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431655/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ARI 0.10 / Asterisk@Home 2.8 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/04/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:asteriskathome:asteriskathome");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80, embedded: 1);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/recordings", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  r = http_send_recv3(method:"GET",item:string(dir, "/includes/main.conf"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like an ARI config file.
  if (egrep(pattern:"(asterisk_mgrpass|ari_admin_password)", string:res))
  {
    report = string(
      "\n",
      "Here are the repeated contents of ARI's config file that\n",
      "that Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_hole(port:port, extra:report);
    exit(0);
  }
}
