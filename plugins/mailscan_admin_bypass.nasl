#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33903);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-3729");
  script_bugtraq_id(30700);
  script_osvdb_id(47673);

  script_name(english:"MailScan WebAdministrator Cookie Authentication Bypass");
  script_summary(english:"Tries to access User Management page");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass authentication and gain administrative access
of a web application on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailScan for Mail Servers, an antivirus /
antispam for mail servers. 

The version of MailScan installed on the remote host allows an
attacker by bypass authentication and gain administrative access to
the application by sending requests without any cookies. 

Note that a number of other vulnerabilities have been reported in
MailScan along with this, although Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/mailscan.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495502/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/17");
 script_cvs_date("$Date: 2016/05/16 14:02:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 10443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:10443);


# Pull up the User Management page.
url = "/WebAdmin/main.dll/dispChangePass";
r = http_send_recv3(method: "GET", item:url, port:port);
if (isnull(r)) exit(0);


# If we can see it.
if (
  ">Preferences>>User Management<" >< r[2] &&
  'url="../main.dll/AddUserpass"' >< r[2]
)
{
  # Let's just make sure it's MailScan for Mail Servers.
  url2 = "/WebAdmin/main.dll/LicenseInfo";
  r = http_send_recv3(method: "GET", item:url2, port:port);
  if (isnull(r)) exit(0);
  if ("MailScan for Mail-Server<" >< r[2])
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to gain access to MailScan's User Management page\n",
        "using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "Note that you may first have to clear any cookies set by the\n",
        "application from your browser.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
