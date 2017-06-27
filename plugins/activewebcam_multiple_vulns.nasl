#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17320);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/09/23 20:00:43 $");

  script_cve_id("CVE-2005-0730", "CVE-2005-0731", "CVE-2005-0732", "CVE-2005-0733", "CVE-2005-0734");
  script_bugtraq_id(12778);
  script_osvdb_id(14638, 14639, 14640, 14641, 14642);

  script_name(english:"Active WebCam Webserver <= 5.5 Multiple Vulnerabilities (DoS, Path Disc)");
  script_summary(english:"Checks for multiple remote vulnerabilities in Active WebCam webserver 5.5 and older");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PY Software's Active WebCam web server running on the
remote host is affected by multiple vulnerabilities:

  o Denial of Service Vulnerabilities.
    A request for a file on floppy drive may result in a dialog
    prompt, causing the service to cease until it is acknowledged by
    an administrator. In addition, requesting the file 'Filelist.html'
    reportedly causes CPU usage on the remote host to increase,
    ultimately leading to denial of service.

  o Information Disclosure Vulnerabilities.
    A request for a nonexistent file will return an error message
    with the installation path for the software. Further, error
    messages differ depending on whether a file exists or is
    inaccessible. An attacker may exploit these issues to gain
    information about the filesystem on the remote host.

Note that while versions 4.3 and 5.5 are known to be affected, earlier
versions are likely to be as well." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df2bc6eb");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Mar/294");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Grab the main page and make sure it's for Active WebCam.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if ('name="GENERATOR" content="Active WebCam' >!< res)
 exit(0, "The web server on port "+port+" is not Active WebCam.");

if (safe_checks()) {
  if (egrep(string:res, pattern:'name="GENERATOR" content="Active WebCam ([0-4][^0-9]|5\\.[0-5] )'))
    security_warning(port);
}
else {
  # Let's request a nonexistent page and see if we can find the install path.
  # Use the number of microseconds in the time for the page.
  now = split(gettimeofday(), sep:".", keep:0);
  page = now[1];

  r = http_send_recv3(method:"GET", item:"/" + page, port:port);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  pat = "The requested file: <B>([^<]+)</B> was not found.";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    path = eregmatch(pattern:pat, string:match);
    if (!isnull(path)) {
      path = path[1];
      if (ereg(string:path, pattern:"^[A-Za-z]:\\")) security_warning(port);
    }
  }
}
