#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25899);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-4261");
  script_bugtraq_id(25323);
  script_osvdb_id(39537);
  script_xref(name:"Secunia", value:"26341");

  script_name(english:"EZPhotoSales Multiple Configuration Files Remote Information Disclosure");
  script_summary(english:"Tries to retrieve config files");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
information disclosure vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running EZPhotoSales, a web-based photo gallery
application for photographers written in PHP. 

The version of EZPhotoSales installed on the remote host fails to
restrict access to configuration files used by the application.  An
unauthenticated, remote attacker can leverage this issue to obtain
sensitive information about the affected application, possibly
enabling him to gain administrative control, which in turn could lead
to arbitrary code execution on the affected host, cross-site scripting
attacks against visitors, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.airscanner.com/security/07080601_ezphotosales.htm" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/475678/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1bea1e2" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to EZPhotoSales 1.9.4 or later, apply the vendor's patch,
or limit access to the application's configuration files using, say, a
.htaccess file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(255);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/16");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/EZPhotoSales", "/OnlineViewing", "/onlineviewing", "/Gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to retrieve one of the config files.
  if (thorough_tests) files = make_list("configuration/galleryConfig.txt", "configuration/config.dat");
  else files = make_list("configuration/galleryConfig.txt");

  foreach file (files)
  {
    r = http_send_recv3(method:"GET",item:string(dir, "/", file), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    hash_lines = 0;
    if (file == 'configuration/config.dat')
    {
      foreach line (split(res, keep:FALSE))
        if (line =~ "^\$1\$[^ ]{32}$") hash_lines++;
    }

    # If...
    if (
      (file == 'configuration/galleryConfig.txt' && 'WebPageTitle: ' >< res) ||
      (file == 'configuration/config.dat' && hash_lines == 2)
    )
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue to obtain the following copy of\n",
        "the application's '", file, "' file from the\n",
        "remote host :\n",
        "\n",
        res
      );
      security_hole(port:port, extra:report);

      exit(0);
    }
  }
}
