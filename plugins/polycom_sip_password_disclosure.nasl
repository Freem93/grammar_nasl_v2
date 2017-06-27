#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55402);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/10/24 19:37:28 $");

  script_bugtraq_id(48316);
  script_osvdb_id(73117);
  script_xref(name:"EDB-ID", value:"17377");
  script_xref(name:"Secunia", value:"44835");

  script_name(english:"Polycom SoundPoint IP Phones reg_1.html SIP Information Disclosure");
  script_summary(english:"Tries to obtain the phone's SIP password.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote telephone device discloses sensitive information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Polycom SoundPoint IP phone hosts a page, 'reg_1.htm',
that discloses the SIP account password for the associated phone line. 
A remote attacker could use this information to mount further
attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?119851ff"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the firmware to version 3.2.2 or greater."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port   = get_http_port(default:80, embedded:TRUE);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

if ("Server: Polycom SoundPoint" >!< banner)
  exit(0, "The web server on port "+port+" does not appear to be from a Polycom SoundPoint device.");

res = http_send_recv3(
  method       : "GET", 
  item         : '/reg_1.htm', 
  port         : port, 
  exit_on_fail : TRUE
);

sip_password = NULL;
if ('name="reg.1.auth.userId"' >< res[2] && 'name="reg.1.auth.password"' >< res[2])
{
  sip_password_pat  = '^.*<input value="([^"]+)" type="password" name="reg\\.1\\.auth\\.password\"';

  foreach line (split(res[2], keep:FALSE))
  {
    matches = eregmatch(string:line, pattern:sip_password_pat);
    if (matches) 
    {
      sip_password = matches[1];
      break;
    }
  }
}

if (!isnull(sip_password))
{
  if (report_verbosity > 0)
  {
    report = '\n  SIP Password : ' + sip_password + '\n';
    security_warning(port:port, extra:report);
  } 
  else security_warning(port);
}
else exit(0, "The remote Polycom device is not affected.");
