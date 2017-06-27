#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18374);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2005-1773");
  script_bugtraq_id(13768);
  script_osvdb_id(16852);

  script_name(english:"Listserv < 14.3-2005a Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Listserv < 14.3-2005a");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
multiple issues." );
  script_set_attribute(attribute:"description", value:
"According to its version number, the Listserv web interface on the
remote host suffers from several critical and as-yet unspecified
vulnerabilities.  An attacker may be able to exploit these flaws to
execute arbitrary code on the affected system or allow remote denial
of service." );
  script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/listserv_2.txt" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/288" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1360cd6d" );
  script_set_attribute(attribute:"solution", value:"Apply the 2005a level set from LSoft." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lsoft:listserv");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# For each CGI directory...
foreach dir (cgi_dirs())
{
  # For each of the possible names for the web interface...
  foreach wa (make_list("wa", "wa.exe", "wa.cgi"))
  {
    # Try to get the version number of the web interface.
    w = http_send_recv3(method:"GET", item:string(dir, "/", wa, "?DEBUG-SHOW-VERSION"), port:port, exit_on_fail:TRUE);
    res = w[2];

    # nb: WA version 2.3.31 corrects the flaw.
    if (res =~ "WA version ([01]\.|2\.([0-2]\.|3\.([0-2]|30)))")
    {
      security_hole(port);
      exit(0);
    }
  }
}
