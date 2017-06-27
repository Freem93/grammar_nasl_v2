#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20321);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-4439");
  script_bugtraq_id(15932);
  script_osvdb_id(21844);
 
  script_name(english:"ELOG Remote Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks for remote buffer overflow vulnerabilities in ELOG");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by remote buffer overflow flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using ELOG, a web-based electronic
logbook application. 

The version of ELOG installed on the remote host crashes when it
receives HTTP requests with excessive data for the 'mode' and 'cmd'
parameters.  An unauthenticated attacker may be able to exploit these
issues to execute arbitrary code on the remote host subject to the
privileges under which the application runs." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040301.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/19");
 script_cvs_date("$Date: 2016/09/08 13:32:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded: 0);

# Make sure the server looks like ELOG.
banner = get_http_banner(port:port);
if (banner && "Server: ELOG HTTP" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    if ((report_paranoia > 1) && (egrep(pattern:"^Server: ELOG HTTP ([01]\.|2\.([0-5]\.|6\.0))", string:banner))) {
      report = string(
        "\n",
        "Nessus determined the flaw exists on the remote host based solely\n",
        "on the version number of ELOG found in the banner."
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
  else {
    # Loop through directories.
    if (thorough_tests) dirs = list_uniq(make_list("/elog", "/demo", cgi_dirs()));
    else dirs = make_list(cgi_dirs());

    if (http_is_dead (port:port))
      exit (0);

    foreach dir (dirs) {
      # Try to exploit the flaw to crash the service.
      r = http_send_recv3(method:"GET",
        item:string(
          dir, "/?",
          "cmd=", crap(20000) ),  port:port );

      if (isnull(r) || strlen(r[2]) == 0) {
        if (http_is_dead(port:port)) {
          security_hole(port);
          exit(0);
        }
      }
      else exit(0);
    }
  }
}
