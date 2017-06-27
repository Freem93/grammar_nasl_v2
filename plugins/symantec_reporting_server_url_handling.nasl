#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38653);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2009-1432");
  script_bugtraq_id(34668);
  script_osvdb_id(54131);
  script_xref(name:"Secunia", value:"34935");
  script_xref(name:"IAVA", value:"2009-A-0037");

  script_name(english:"Symantec Reporting Server Improper URL Handling Exposure");
  script_summary(english:"Tries to exploit URL handling weakness");
 
  script_set_attribute(attribute:"synopsis", value:
"The login page in the remote web server contains a URL handling
error.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Symantec Reporting Server, a component of
Symantec AntiVirus Corporate Edition, Symantec Client Security, and
Symantec Endpoint Protection Manager that serves to create reports about
the use of Symantec antivirus products in an enterprise environment. 

The installed version of Reporting Server includes user-supplied input
to the 'MSG' parameter of the 'Reporting/login/login.php' script on the
login page.  By tricking an authorized user into clicking on a specially
crafted link, an attacker can cause an arbitrary message to be
displayed, which in turn could facilitate phishing attacks against the
affected site.");
  # http://www.liquidmatrix.org/blog/2009/04/29/on-dealing-with-symantec-for-vuln-disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed674302");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2009&suid=20090428_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42400bc6");
  script_set_attribute(attribute:"solution", value:"Upgrade as described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:reporting_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:antivirus");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:antivirus_central_quarantine_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:client_security");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8014);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Unless we're paranoid, make sure it's IIS (required for Symantec Reporting Server).
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if(!banner || "Microsoft-IIS" >!< banner) exit(0);
}

magic = string(SCRIPT_NAME, "-", unixtime());
url = "/Reporting/Login/Login.php?MSG=" + magic;

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if (
  magic >< res[2] &&
  "<title>Reporting - Log" >< res[2] &&
  '<input type="hidden" name="destination"' >< res[2]
)
{
  if (report_verbosity > 0 )
  { 
    report = string(
      "\n",
      "Nessus was able to verify the issue with the following URL :\n",
      "\n", 
      "  ", build_url(port:port, qs:url), "\n"
  );
   security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
