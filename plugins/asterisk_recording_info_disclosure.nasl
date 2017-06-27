#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21304);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-2021");
  script_bugtraq_id(17641);
  script_osvdb_id(24806);

  script_name(english:"Asterisk Recording Interface (ARI) misc/audio.php recording Parameter Traversal Arbitrary File Access");
  script_summary(english:"Requests a file using ARI's misc/audio.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Asterisk Recording Interface (ARI), a
web-based portal for the Asterisk PBX software. 

The version of ARI installed on the remote host reportedly allows an
unauthenticated attacker to retrieve arbitrary sound files, such as
voicemail messages, and to determine the existence of other files on
the remote host by passing a specially crafted path to the 'recording'
parameter of the 'misc/audio.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431655/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ARI 0.10 / Asterisk@Home 2.8 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/04/20");
 script_cvs_date("$Date: 2016/05/04 14:21:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:asteriskathome:asteriskathome");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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
  # Request a file known to exist; a vulnerable version will complain 
  # the file can't be used while a patched one will complain the file
  # isn't found because it encrypts the parameter.
  file = "../version.inc";
  r = http_send_recv3(method:"GET", port:port,
    item:string(
      dir, "/misc/audio.php?",
      "recording=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  if (string("Cannot use file: ", file) >< res)
  {
    security_warning(port);
    exit(0);
  }
}
