#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64485);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/07 11:50:04 $");

  script_bugtraq_id(56492);
  script_osvdb_id(87286);
  
  script_name(english:"UnrealIRCd Unspecified DoS");
  script_summary(english:"Checks the version of the remote ircd");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a denial of service
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of UnrealIRCd that could crash
when it receives certain raw messages. 
 
An attacker could exploit this flaw to disable the service remotely.");
  script_set_attribute(attribute:"see_also", value:"http://www.unrealircd.com/txt/unrealsecadvisory.20121112.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to UnrealIRCd 3.2.10 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/06");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unrealircd:unrealircd"); 
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "UnrealIRCd";

port = get_service(svc:"irc", default:6667, exit_on_fail:TRUE);

banner = get_kb_item_or_exit("irc/banner/"+port);
if ("Unreal" >!< banner) audit(AUDIT_NOT_DETECT, appname, port);

version = ereg_replace(string:banner, pattern: ": *[^ ]+ +[0-9]+ +[a-zA-Z0-9]+ +([^ ]+) +[^ ]+ *:(.*)", replace: "\1 \2");
match = eregmatch(pattern:"Unreal(([0-9])(\.[0-9])+([\-a-zA-Z0-9]+)?)\.\s+([a-zA-Z]+)", string:version);
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, appname, port);

ver = match[1];
flags = match[5];

if (
  "W" >< flags && 
  "e" >< flags && 
  "winsslfix" >!< version &&
  egrep(pattern:"Unreal3\.2\.(9|10-rc1)($|[^0-9])", string:version)
) 
{
  if (report_verbosity > 0)
  {
    report =        
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : 3.2.10' +
        '\n';
    security_warning(port:port,extra:report);
  } 
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, ver);
