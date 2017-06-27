#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62718);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2012-3001");
  script_bugtraq_id(56165);
  script_osvdb_id(86570);
  script_xref(name:"CERT", value:"841851");

  script_name(english:"Mutiny < 4.5-1.12 Unspecified Network Interface Menu Remote Command Injection");
  script_summary(english:"Checks version of Mutiny");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a network monitoring application that is
affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Mutiny earlier than 4.5-1.12. 
It is, therefore, reportedly affected by a command injection 
vulnerability that could allow an authenticated attacker to execute 
arbitrary commands via the network interface menu. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mutiny.com/releasehistory.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.5-1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mutiny Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mutiny:standard");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mutiny_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mutiny");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "mutiny",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
loc = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Mutiny", loc);

# format our version from x.x-x.xx to x.x.x.xx
ver1 = str_replace(string:version, find:'-', replace:'.');
ver = split(ver1, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 4.5-1.12 are affected
if (
  (ver[0] < 4) ||
  (
    ver[0] == 4 && 
    (
      ver[1] < 5 ||
      (
        ver[1] == 5 && 
        (
          ver[2] < 1 ||
          (ver[2] == 1 && ver[3] < 12)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.5-1.12' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Mutiny", loc, version);
