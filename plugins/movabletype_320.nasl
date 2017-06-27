#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19776);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id(
    "CVE-2005-3101",
    "CVE-2005-3102",
    "CVE-2005-3103",
    "CVE-2005-3104"
  );
  script_bugtraq_id(14910, 14911, 14912);
  script_osvdb_id(19601, 19602, 19603, 19604);

  script_name(english:"Movable Type < 3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Movable Type");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Movable Type installed on the remote host is affected
by multiple vulnerabilities :

  - The application allows an attacker to enumerate valid
    usernames because its password reset functionality
    returns different errors depending on whether the
    supplied username exists. (CVE-2005-3101)

  - The application allows privileged users to upload files
    with arbitrary extensions, possibly outside the web
    server's document directory. (CVE-2005-3102)

  - The application is affected by a cross-site scripting
    vulnerability because it fails to properly sanitize
    certain fields when creating new blog entries.
    (CVE-2005-3103)

  - The mt-comments.cgi script allows attackers to redirect
    users to other sites via URLs in comments.
    (CVE-2005-3104)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Nov/100"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Movable Type 3.2 or later and grant only trusted users the
ability to upload files via the administrative interface."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("movabletype_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/movabletype", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : "movabletype",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Movable Type", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 2)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url, version);
