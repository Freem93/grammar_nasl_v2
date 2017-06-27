#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71899);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/14 20:50:07 $");

  script_cve_id("CVE-2013-5773");
  script_bugtraq_id(63066);
  script_osvdb_id(98464);

  script_name(english:"Oracle Containers for J2EE Component Unspecified XSS");
  script_summary(english:"Checks for insecure cookies");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by an unspecified cross-site scripting
issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Oracle Application server is affected by an unspecified
cross-site scripting vulnerability. Specifically, installations that
do not set the 'HttpOnly' flag in session cookies are vulnerable."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=1586861.1");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(
    attribute:"solution",
    value:
"See Oracle's Doc ID 1586861.1 for configuration change instructions
that mitigate this vulnerability by setting the 'HttpOnly' flag in
session cookies."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80);
server_name = http_server_header(port:port);

if ("Oracle-Application-Server-10g/10.1.3.5.0" >!< server_name)
  audit(AUDIT_NOT_LISTEN, "Oracle Application Server", port);

# high value set on follow_redirect in case we are sent to login
# page
res = http_send_recv3(port:port,
                      method:'GET',
                      item:'/',
                      follow_redirect:5,
                      exit_on_fail:TRUE);

vuln_cookie = '';
found_cookie = FALSE;
foreach line (split(res[1], keep:FALSE))
{
  if ('set-cookie' >< tolower(line))
  {
    found_cookie = TRUE;
    if ('httponly' >!< tolower(line))
    {
      vuln_cookie = line;
      break;
    }
  }
}

if (!found_cookie)
  exit(0, 'No session cookies found for Oracle Application Server on port ' + port + '.');

if (vuln_cookie != '')
{
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
    '\n' + 'The remote Oracle Application Server does not appear to be' +
    '\n' + 'configured to prevent the vulnerability due to the presence of' +
    '\n' + 'a cookie that is not protected by the \'HttpOnly\' flag :' +
    '\n' +
    '\n' +  vuln_cookie + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle Application Server", port);
