#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73611);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id(
    "CVE-2014-2859",
    "CVE-2014-2860",
    "CVE-2014-2861",
    "CVE-2014-2862",
    "CVE-2014-2863",
    "CVE-2014-2864",
    "CVE-2014-2865",
    "CVE-2014-2866",
    "CVE-2014-2867",
    "CVE-2014-2868",
    "CVE-2014-2869",
    "CVE-2014-2870",
    "CVE-2014-2871",
    "CVE-2014-2872",
    "CVE-2014-2873",
    "CVE-2014-2874"
  );
  script_bugtraq_id(66813);
  script_osvdb_id(
    105768,
    105769,
    105770,
    105771,
    105772,
    105773,
    105774,
    105775,
    105776,
    105777,
    105778,
    105779,
    105780
  );
  script_xref(name:"CERT", value:"437385");

  script_name(english:"CommonSpot < 7.0.2 / 8.0.3 / 9.0.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of CommonSpot");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a ColdFusion-based application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the CommonSpot install hosted on the
remote web server is affected by multiple vulnerabilities :

  - An access restriction bypass via a direct request.
    (CVE-2014-2859)

  - Multiple cross-site scripting (XSS) vulnerabilities.
    (CVE-2014-2860, CVE-2014-2861)

  - Improper authorization checks in unspecified requests
    can allow a remote, unauthenticated attacker to perform
    unauthorized actions. (CVE-2014-2862)

  - Multiple path traversal vulnerabilities allow remote,
    unauthenticated attackers to request full pathnames in
    parameters. (CVE-2014-2863)

  - Multiple directory traversal vulnerabilities.
    (CVE-2014-2864)

  - The application fails to restrict the use of a NULL
    byte, which can be used to bypass access restrictions.
    (CVE-2014-2865)

  - The application uses client JavaScript code for access
    restrictions, which can be bypassed with attacker-
    controlled JavaScript. (CVE-2014-2866)

  - Unrestricted file uploads could allow for dangerous
    file types to be added to the server. (CVE-2014-2867)

  - Multiple pages allow a remote attacker to override
    ColdFusion variables via HTTP GET requests.
    (CVE-2014-2868)

  - Multiple pages allow for information disclosure.
    (CVE-2014-2869)

  - The application stores credentials in plaintext in the
    underlying application database by default.
    (CVE-2014-2870)

  - The application transmits credentials in cleartext via
    HTTP.  (CVE-2014-2871)

  - Multiple directory listings allow for potential access
    to sensitive information. (CVE-2014-2872)

  - The application allows unauthenticated access to log
    files allowing for information disclosure.
    (CVE-2014-2873)

  - The application allows remote, unauthenticated attackers
    to execute arbitrary commands with arbitrary parameters.
    (CVE-2014-2874)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2859.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2860.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2861.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2862.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2863.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2864.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2865.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2866.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2867.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2868.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2869.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2870.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2871.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2872.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2873.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2874.html");
  script_set_attribute(attribute:"see_also", value:"http://www.paperthin.com/support/tech-specs.cfm");
  script_set_attribute(attribute:"solution", value:"Upgrade to CommonSpot version 7.0.2 / 8.0.3 / 9.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paperthin:commonspot_content_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("commonspot_web_detect.nbin");
  script_require_keys("www/commonspot");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = 'CommonSpot';

install = get_install_from_kb(
  appname : "commonspot",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_loc = build_url(port:port, qs:dir + "/index.cfm");

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

fix = NULL;
ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 7.0.2 / 8.x < 8.0.3 / 9.0.0 are vulnerable
if (ver[0] < 7)
{
  fix = '7.0.2 / 8.0.3 / 9.0.0 or later';
}
else if (ver[0] == 7 && ver[1] == 0 && ver[2] < 2)
{
  fix  = '7.0.2';
}
else if (ver[0] == 8 && ver[1] == 0 && ver[2] < 3)
{
  fix = '8.0.3';
}

if (!isnull(fix))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);

