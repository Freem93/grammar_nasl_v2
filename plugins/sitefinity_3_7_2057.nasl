#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(51119);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_bugtraq_id(44911);
  script_xref(name:"EDB-ID", value:"15563");

  script_name(english:"Sitefinity CMS Arbitrary File Upload");
  script_summary(english:"Checks version of Sitefinity CMS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An ASP.NET application hosted on the remote web server may be
affected by an arbitrary file upload vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Sitefinity ASP.NET CMS install hosted on the remote web server
may be affected by an arbitrary file upload vulnerability because it
does not properly sanitize input data.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in Sitefinity's banner."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51df3fa1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sitefinity 3.7.2057 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("sitefinity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sitefinity");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);
install = get_install_from_kb(appname:'sitefinity', port:port, exit_on_fail:TRUE);
dir = install['dir'];

if (install['ver'] == UNKNOWN_VER)
  exit(1, "Sitefinity was detected on port "+port+" but the version could not be determined.");

# Remove ':{num}' from the end of the version string
version = install['ver'] - strstr(install['ver'], ":");

if (ver_compare(ver:version, fix:'3.7.2057', strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Install location  : ' + build_url(port:port, qs:dir+'/sitefinity/login.aspx') +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.7.2057.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Sitefinity CMS install at "+build_url(port:port, qs:dir+'/sitefinity/login.aspx')+" is version "+version+" and thus not affected.");
