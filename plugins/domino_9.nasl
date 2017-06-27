#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66240);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id(
    "CVE-2012-2159",
    "CVE-2012-2161",
    "CVE-2013-0488",
    "CVE-2013-0489"
  );
  script_bugtraq_id(53884, 58648, 58649, 58715);
  script_osvdb_id(82711, 82754, 91588, 91589, 91838);

  script_name(english:"IBM Lotus Domino 8.5.x Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Lotus Domino on the remote host
is 8.5.x and is, therefore, affected by the following vulnerabilities :

  - Some scripts inside the Web Help application are
    vulnerable to open redirect attacks. (CVE-2012-2159)

  - The Web Help component contains a reflected cross-site
    scripting vulnerability. (CVE-2012-2161)

  - User-input validation errors exist related to the
    'Web Administrator' client as well as the 'Src'
    parameter and 'x.nsf' script that could allow cross-site
    scripting attacks. (CVE-2013-0488, BID 58715)

  - A user-input validation error exists related to the
    'Web Administrator' client that could allow cross-site
    request forgery attacks. (CVE-2013-0489)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Mar/219");
  # Fix Pack / Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27010592#ver90");
  # Bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21627597");
  # PSIRT notice
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a70209a1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Domino 9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl", "http_version.nasl");
  script_require_keys("Domino/Version");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're being paranoid, make sure a Domino web server is listening.
if (report_paranoia < 2)
{
  port = get_http_port(default:80);
  banner = get_http_banner(port:port);
  if (!banner) audit(AUDIT_NO_BANNER, port);
  if ("Domino" >!< banner) audit(AUDIT_NOT_LISTEN, "IBM Lotus Domino", port);
}
else port = 0;

# Check the version of Domino installed.
ver = get_kb_item_or_exit("Domino/Version");

# Check that version is granular enough
if (ver == "8") exit(1, "The version "+ver+" on port "+port+" is not granular enough to make a determination.");

# Check that version is 8.5.x
if (ver !~ "^8\.5($|[^0-9])") audit(AUDIT_NOT_LISTEN, "IBM Lotus Domino 8.5.x", port);

# Affected 8.5.x
if (ver =~ "^8\.5($|[^0-9])")
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.0' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Lotus Domino", port, ver);
