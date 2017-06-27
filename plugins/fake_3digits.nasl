#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(32376);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_name(english:"Fake SMTP/FTP Server Detection (possible backdoor)");

 script_set_attribute(attribute:"synopsis", value:
"The remote service seems to be a backdoor" );
 script_set_attribute(attribute:"description", value:
"Although this service answers with 3 digit ASCII codes
like FTP, SMTP or NNTP servers, it sends back different codes
when several NOOP commands are sent in a row.

This is probably a backdoor; in this case, your system is 
compromised and an attacker can control it remotely." );
 script_set_attribute(attribute:"solution", value:
"Disinfect or reinstall your operating system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks that the '3 digits' server answers correctly");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/three_digits");
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#

exit(0); # Deprecated
