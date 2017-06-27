#
# (C) Tenable Network Security, Inc.
#
# Date: 10 Jun 2004 14:26:29 -0000
# From: <msl@velmans-industries.nl>
# To: bugtraq@securityfocus.com
# Subject: Edimax 7205APL
#

include("compat.inc");

if (description)
{
 script_id(12269);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/11/05 16:18:19 $");

 script_bugtraq_id(10512);
 script_osvdb_id(7159);
 script_xref(name:"Secunia", value:"11849");

 script_name(english:"EDIMAX Wireless AP Default Password Check");
 script_summary(english:"EDIMAX hidden password check.");

 script_set_attribute(attribute:"synopsis", value:
"The remote access point has an account that uses a default password.");
 script_set_attribute(attribute:"description", value:
"The remote EDIMAX Wireless Access Point ships with a default account
('guest' / '1234') that has backup privileges on the remote
configuration file. A remote attacker can exploit this to obtain a
plaintext password for the administrator account by doing a backup of
the remote configuration file.");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix. As a temporary workaround, disable the
web server or filter the traffic to this access point web server via
an upstream firewall.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 80);

 exit(0);
}

# start check

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

creds = make_array(
  "guest", "1234",
  "admin", "1234"
);

info = '';

r = http_send_recv3(method:"GET", item:"/", port:port, exit_on_fail:TRUE);
# make sure we are looking at a device that requires authentication, and that
# our POST login condition text looked for below is not already displayed
# (this should never happen)
if("WWW-Authenticate" >!< r[1] || "EDIMAX Access Point Web Management" >< r[2])
  audit(AUDIT_LISTEN_NOT_VULN, "web server", port);

# from firmware:
# <title>EDIMAX Access Point Web Management</title>
foreach username (keys(creds))
{
  password = creds[username];
  r = http_send_recv3(method:"GET", item:"/", port:port, username:username, password:password, exit_on_fail:TRUE);
  if ("EDIMAX Access Point Web Management" >< r[2])
  {
    info += '\n  Username : ' + username +
            '\n  Password : ' + password + '\n';
  }
}

if(info == '')
  audit(AUDIT_LISTEN_NOT_VULN, "web server", port);

report = '\nNessus was able to login to the remote device using the following'+
         '\ndefault credentials :\n' + info;
security_hole(port:port, extra:report);
