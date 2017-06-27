#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#
# Vulnerability found by Russell Handorf <rhandorf@mail.russells-world.com>


include("compat.inc");

if (description)
{
  script_id(10724);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/15 13:39:08 $");

  script_cve_id("CVE-2001-1430");
  script_bugtraq_id(3017);
  script_osvdb_id(602);

  script_name(english:"Cayman DSL Router Single Character String Authentication Bypass.");
  script_summary(english:"Tries to login using default credentials");
 
  script_set_attribute(
   attribute:"synopsis",
   value:"The remote router is secured with a default username and password."
 );
  script_set_attribute(attribute:"description",  value:
"The remote host appears to be a Cayman DSL router.  This device
contains an insecure user account - it was possible to login with a
username of '{' and no password."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2001/Jul/183"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Give the account a strong password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cayman:3220-h_dsl_router");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('telnet_func.inc');
include('global_settings.inc');
include('misc_func.inc');


os = get_kb_item("Host/OS");
if ( ! os && ! thorough_tests ) exit(0, "Nessus was not able to identify the OS on the remote host and 'thorough_tests' are not enabled.");
if ( "Cayman" >!< os ) audit(AUDIT_OS_NOT, "Cayman");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = raw_string(0x7D);

banner = get_telnet_banner(port:port);
if ( ! banner || "login" >!< banner ) exit(0, "The Telnet banner on port "+ port +" is not for a login to a Cayman DSL Router.");

soc = open_sock_tcp(port);
if(soc)
{
  buf = telnet_negotiate(socket:soc);
  if("login" >< buf)
  {
    r = recv(socket:soc, length:2048);
    b = buf + r;
    send(socket:soc, data:login + '\r\n');
    r = recv(socket:soc, length:2048);
    send(socket:soc, data:'\r\n');
    r = recv(socket:soc, length:4096);
    if("completed login" >< b)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' +
          'Nessus was able to gain access using the following information :\n' +
          '\n' +
          '  User     : root\n' +
          '  Password : pass\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      close(soc);
      exit(0);
    }
  }
  close(soc);
  audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_SOCK_FAIL, port);
