#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14223);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/01/15 21:39:12 $");

 script_cve_id("CVE-2004-0792");
 script_bugtraq_id(10938);
 script_osvdb_id(8829);

 script_name(english:"rsync sanitize_path() Function Arbitrary File Disclosure");
 script_summary(english:"Determines if rsync is running.");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be accessed from the remote host.");
 script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in rsync due to
improper validation of user-supplied input to the sanitize_path()
function. An unauthenticated, remote attacker can exploit this, via
a specially crafted path, to generated an absolute filename in place
of a relative filename, resulting the disclosure of arbitrary files.
However, successful exploitation requires that the rsync daemon is not
running chrooted.

Note that since rsync does not advertise its version number and since
there are few details about this flaw at this time, this might be a
false positive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to rsync version 2.6.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("rsync_modules.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/rsyncd", 873);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("Services/rsyncd");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsyncd/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 28 are not vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-8])", string:welcome))
{
 security_warning(port);
}
