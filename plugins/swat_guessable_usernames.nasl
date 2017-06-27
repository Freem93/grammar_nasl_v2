#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10590);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2000-0938");
  script_osvdb_id(487);

  script_name(english:"Samba Web Administration Tool (SWAT) Error Message Username Enumeration");
  script_summary(english:"Detect SWAT server port");

  script_set_attribute(attribute:'synopsis', value:
'The remote service is vulnerable to information disclosure.');
  script_set_attribute(
    attribute:'description',
    value:
'The remote SWAT server replies with different error codes when it is
issued a bad user name or a bad password.

An attacker may use this flaw to obtain the list of user names of the
remote host by a brute-force attack.

As SWAT does not log login attempts, an attacker may use this flaw even
more effectively.'
  );
  script_set_attribute(attribute:'solution', value:'Upgrade to the latest Samba packages.');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:'see_also', value:'http://seclists.org/bugtraq/2000/Oct/442');

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("swat_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/swat");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/swat");
if(!port) exit(0);

if (! get_port_state(port)) exit(0);

 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  #
  # First attempt - we try to log in as nosuchuser1234:nopass
  #
  w = http_send_recv3(method:"GET", item:"/", port:port,
    username: "nosuchuser1234", password: "nopass");
  if (isnull(w)) exit(1, "the web server did not answer");
  code1 = w[0];

  #
  # Second attempt - we try to log in as root:nopass
  #
  w = http_send_recv3(method:"GET", item:"/", port:port,
    username: "root", password: "nopass");
  if (isnull(w)) exit(1, "the web server did not answer");
  code2 = w[0];

  if(("401" >< code1)  &&
     ("401" >< code2))
     {
       if(code1 != code2)security_warning(port);
      }
 }
