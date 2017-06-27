#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11603);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/05/26 01:15:50 $");

 script_bugtraq_id(7323);
 script_osvdb_id(55137);

 script_name(english:"Mac OS X Directory Service Connection Saturation Remote DoS");
 script_summary(english:"Crashes the remote MacOS X Directory Service");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to disable the remote service (probably MacOS X's
directory service) by making multiple connections to this port.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA22265");
 script_set_attribute(attribute:"solution", value:"Upgrade to MacOS X 10.2.5 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(625);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 625;

if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 for(i=0;i<250;i++)
 {
  soc = open_sock_tcp(port);
  if(!soc){ security_warning(port); exit(0); }
 }
}
