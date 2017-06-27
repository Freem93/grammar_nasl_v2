#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97355);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/12 17:36:04 $");

  script_cve_id(
    "CVE-2016-8934",
    "CVE-2017-1121"
  );
  script_bugtraq_id(
    95154,
    96164
  );
  script_osvdb_id(
    148285,
    151891
  );

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.43 / 8.0 < 8.0.0.14 / 8.5 < 8.5.5.12 / 9.0 < 9.0.0.3 Admin Console Multiple XSS");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple XSS
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to 7.0.0.43, 8.0 prior to 8.0.0.14, 8.5 prior to
8.5.5.12, or 9.0 prior to 9.0.0.3. It is, therefore, affected by
multiple cross-site scripting (XSS) vulnerabilities in the Admin
Console due to a failure to validate input before returning it to
users. An authenticated, remote attacker can exploit these, via a
specially crafted URL, to execute arbitrary script code in a user's
browser session within the security context of the hosting website.

Note that Nessus has not checked for the Interim Fix for these issues
but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21992315");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21997743");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24043318");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 43
(7.0.0.43) / 8.0 Fix Pack 14 (8.0.0.14) / 8.5 Fix Pack 12 (8.5.5.12) /
9.0 Fix Pack 3 (9.0.0.3) or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply
Interim Fix PI73367. See the vendor advisory for more details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881, 9001);
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8880, embedded:FALSE);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^([789](\.0)?|8\.5)$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = "PI73367"; # Interim fix
note = NULL;

if (version =~ "^9\.0\.")
{
  fix = '9.0.0.3';
  min = '9.0.0.0';
  pck = " (Fix Pack 3)";
}
else if (version =~ "^8\.5\.5($|[^0-9])")
{
  fix = '8.5.5.12';
  min = '8.5.5.0';
  pck = " (Fix Pack 12)";
}
else if (version =~ "^8\.5\.0($|[^0-9])")
{
  fix = '8.5.0.2';
  min = '8.5.0.0';
  pck = " (Fix Pack 2)";
  note = " with interim fix " + itr;
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.14';
  min = '8.0.0.0';
  pck = " (Fix Pack 14)";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.43';
  min = '7.0.0.0';
  pck = " (Fix Pack 43)";
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report =
  '\n  Version source    : ' + source  +
  '\n  Installed version : ' + version;

if (!isnull(note) && ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) <=  0)
    report +=
      '\n  Fixed version     : ' + fix + pck + note;
else if (isnull(note) && ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) <  0)
    report +=
      '\n  Fixed version     : ' + fix + pck +
      '\n  Interim fix       : ' + itr;
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report += '\n';

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report, xss:TRUE);
