#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65196);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2012-6084");
  script_bugtraq_id(57085);
  script_osvdb_id(88839);

  script_name(english:"Charybdis IRCd m_capab.c Denial of Service");
  script_summary(english:"Checks the version of the remote Charybdis IRCd");

  script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Charybdis IRCd that is affected
by a denial of service (DoS) vulnerability.  An issue exists in the
'CAPAB' module in 'm_capab.c' that causes servers to improperly handle
negotiation handshakes. 

An unauthenticated, remote attacker could exploit this issue with a
specially crafted request, impacting the availability of the service.");
  script_set_attribute(attribute:"see_also", value:"http://rabbit.dereferenced.org/~nenolod/ASA-2012-12-31.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Charybdis 3.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ratbox:ircd-ratbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ircd.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/irc", 6667);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Charybdis IRCd";

port = get_service(svc:"irc", default:6667, exit_on_fail:TRUE);

banner = get_kb_item_or_exit("irc/banner/"+port);
if ("charybdis" >!< banner) audit(AUDIT_NOT_DETECT, appname, port);

version = ereg_replace(string:banner, pattern:": *[^ ]+ +[0-9]+ +[a-zA-Z0-9]+ +([^ ]+) +[^ ]+ *:(.*)", replace:"\1 \2");
pattern = "charybdis-?(([0-9\.]+-?([0-9]+)?)(|-?dev\d?|-?rc\d?)?)\(";
match = eregmatch(pattern:pattern, string:version);
if (isnull(match)) exit(1, "Failed to extract the version of "+appname+" listening on port "+port+".");
full_ver = match[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed = '3.4.2';
if (full_ver =~ "^([0-2]\.|3\.[0-3]\.|3\.4\.[0-1]($|[^0-9])|3\.4\.2[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
        '\n  Version source    : ' + chomp(banner) +
        '\n  Installed version : ' + full_ver +
        '\n  Fixed version     : ' + fixed + '\n';
    security_warning(port:port,extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, full_ver);
