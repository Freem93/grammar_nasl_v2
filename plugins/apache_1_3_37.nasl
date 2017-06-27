#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(31654);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");

 script_cve_id("CVE-2006-3747");
 script_bugtraq_id(19204);
 script_osvdb_id(27588);
 script_xref(name:"EDB-ID", value:"3680");
 
 script_name(english:"Apache < 1.3.37 mod_rewrite LDAP Protocol URL Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Apache is vulnerable to an off-by-one buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache which is
older than 1.3.37. 

This version contains an off-by-one buffer overflow in the mod_rewrite
module." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jul/671");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive//443870");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.37 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("apache_http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item('www/'+port+'/apache');

# Check if we could get a version first,  then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'Apache');
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokesn Major/Minor
# was used

if (version =~ '^1(\\.3)?$') audit(AUDIT_VER_NOT_GRANULAR, 'Apache', port, version);
if (version !~ "^\d+(\.\d+)*$") audit(AUDIT_NONNUMERIC_VER, 'Apache', port, version);
if (version =~ '^1\\.3' && ver_compare(ver:version, fix:'1.3.37') == -1)
{
  if (report_paranoia > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.37\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Apache', port, version);
