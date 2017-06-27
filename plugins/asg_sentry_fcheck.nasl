#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34397);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-1322");
  script_bugtraq_id(28188);
  script_osvdb_id(43086);
  script_xref(name:"Secunia", value:"29289");

  script_name(english:"ASG-Sentry File Check Utility /snmx-cgi/fcheck.exe Arbitrary File Overwrite");
  script_summary(english:"Checks fcheck.exe's help message");

 script_set_attribute(attribute:"synopsis", value:
"A CGI script on the remote web server can be used to overwrite
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The File Check Utility (fcheck.exe) included with the version of
ASG-Sentry installed on the remote host fails to sanitize input before
creating index files with filenames and checksums.  An unauthenticated
remote attacker can leverage this issue to overwrite existing files
with either no data or a list of filenames and checksums or possibly
to use up CPU and disk resources by scanning, say, 'C:\'. 

Note that there are reportedly several other issues affecting this
version of ASG-Sentry, including buffer overflows, although Nessus has
not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/asgulo-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Mar/128" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/14");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("asg_sentry_cgi_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6161);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6161);

# Test an install.
install = get_kb_item(string("www/", port, "/asg_sentry"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Pull up the usage message.
  url = string(dir, "/fcheck.exe?-h");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it's ASG's fcheck.exe and...
    'ASG File Check Utility' >< res &&
    # it supports creating baseline files.
    'fcheck -b' >< res
  ) security_hole(port);
}
