#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67192);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/05 20:00:33 $");

  script_cve_id("CVE-2012-6277", "CVE-2013-0486", "CVE-2013-0487");
  script_bugtraq_id(56610, 58646, 58652);
  script_osvdb_id(87619, 91586, 91587);
  script_xref(name:"CERT", value:"849841");

  script_name(english:"IBM Lotus Domino 8.5.x < 8.5.3 FP 4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Lotus Domino on the remote host
is 8.5.x earlier than 8.5.3 FP4.  It is, therefore, affected by the
following vulnerabilities :

  - An error exists related to the 'Autonomy KeyView' file
    parser that could allow arbitrary code execution.
    (CVE-2012-6277)

  - A memory leak error exists that could allow an attacker
    to crash the application. (CVE-2013-0486)

  - An error exists related to time-limited authentication
    credentials and the Java console that could allow an
    authenticated user to elevate privileges.
    (CVE-2013-0487)");
  # Fix Pack / Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27010592#ver853");
  # Bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21627597");
  # PSIRT notice
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a70209a1");
  # http://www-10.lotus.com/ldd/fixlist.nsf/5c087391999d06e7852569280062619d/1ae049e892ad2e4a85257b65006e0455?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31a92d24");
  # http://www-10.lotus.com/ldd/fixlist.nsf/5c087391999d06e7852569280062619d/0ed99b8fd6da4f5b85257b6600003fb6?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1992751");
  # http://www-10.lotus.com/ldd/fixlist.nsf/5c087391999d06e7852569280062619d/230a515eac105bc285257b58000057ed?OpenDocument
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5330b7e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Domino 8.5.3 FP4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

# Affected 8.5.x < 8.5.3 FP4
if (
  ver == "8.5"                    ||
  ver =~ "^8\.5 FP[0-9]"          ||
  ver =~ "^8\.5\.[0-2]($|[^0-9])" ||
  ver == "8.5.3"                  ||
  ver =~ "^8\.5\.3 FP[0-3]($|[^0-0])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 8.5.3 FP4' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Lotus Domino", port, ver);
