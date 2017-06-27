#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33951);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
 script_name(english: "Generic Backdoor Detection (banner check)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host may be compromised." );
 script_set_attribute(attribute:"description", value:
"The remote service tries to mimic a known service. 

This is probably a backdoor.  In this case, your system may be
compromised, and an attacker can control it remotely." );
 script_set_attribute(attribute:"solution", value:
"Check and disinfect / reinstall your operating system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

	 
 script_summary(english: "Look for suspicious banner");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');

# I'm not sure this will not generate FP
if (! experimental_scripts) exit(0);

ports = get_kb_list("Services/220backdoor");

if (! isnull(ports))
  foreach port (ports) 
    if (port && get_port_state(port))
    {
      security_hole(port:port, extra:'\n'+
"Although this service sends back a 220 code on connection, 
like SMTP, NNTP or FTP servers, there is no banner behind it." );
      set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
    }
