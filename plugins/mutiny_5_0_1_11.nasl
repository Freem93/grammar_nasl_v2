#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66497);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-0136");
  script_bugtraq_id(59883);
  script_osvdb_id(93444);
  script_xref(name:"CERT", value:"701572");

  script_name(english:"Mutiny < 5.0-1.11 Multiple Directory Traversals");
  script_summary(english:"Checks version of Mutiny");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a network monitoring application that is
affected by multiple directory traversal vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote server hosts a version of Mutiny prior to 5.0-1.11.  It is,
therefore, reportedly affected by multiple directory traversal
vulnerabilities that could allow an authenticated attacker to upload,
delete, and move files on the remote system with root privileges.  The
functions for UPLOAD, DELETE, CUT, and COPY used in the 'Documents'
section of the web frontend of Mutiny are affected. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  # https://community.rapid7.com/community/metasploit/blog/2013/05/15/new-1day-exploits-mutiny-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e896696");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.0-1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mutiny 5 Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mutiny:standard");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mutiny_detect.nasl");
  script_require_keys("www/mutiny");
  script_require_ports("Services/www", 80);
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

# Versions < 5.0-1.11 are affected
if (
  ver[0] < 5 ||
  (
    ver[0] == 5 &&
    (
      ver[1] == 0 &&
      (
        ver[2] < 1 ||
        (ver[2] == 1 && ver[3] < 11)
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
      '\n  Fixed version     : 5.0-1.11' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Mutiny", loc, version);
