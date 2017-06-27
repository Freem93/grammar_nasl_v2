#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description)
{
  script_id(14712);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_bugtraq_id(11144);
  script_osvdb_id(9789, 10727);

  script_name(english:"MailEnable SMTP Connector Service DNS MX Response DoS");
  script_summary(english:"Checks for DNS Lookup DoS Vulnerability in MailEnable SMTP Connector Service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host has a application that is affected by a denial of
service vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running at least one 
instance of MailEnable's SMTP Connector service.  A flaw exists in 
both the Standard Edition 1.7x and Professional Edition 1.2x/1.5a-e 
that results in this service crashing if it receives a DNS response 
with over 100 MX records.  A remote attacker can exploit this to 
perform a DoS attack against the SMTP server on the target." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Standard Edition 1.8 / Professional
Edition 1.5e or greater." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");
  script_family(english:"SMTP problems");
  script_dependencie("find_service1.nasl", "global_settings.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_service(svc:"smtp", default:25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

debug_print("searching for DNS Lookup DoS vulnerability in MailEnable SMTP Connector service on ", host, ":", port, ".\n");

# We have to rely only on the banner, which unfortunately is not 
# updated by the hotfix.
banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);
debug_print("banner =>>", banner, "<<.\n");
if (banner !~ "Mail(Enable| Enable SMTP) Service") exit(0);

# nb: Standard Edition seems to format version as "1.71--" (for 1.71)
#     while Professional Edition formats it like "0-1.2-" (for 1.2).
ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:banner, icase:TRUE);
if (ver == NULL) {
  exit(1, "cannot determine version number of MailEnable's SMTP Connector service");
}
if (ver[1] == NULL) {
  edition = "Standard";
}
else if (ver[1] == "0-") {
  edition = "Professional";
}
if (isnull(edition)) {
  exit(1, "cannot determine edition of MailEnable's SMTP Connector service");
}
ver = ver[2];
debug_print("MailEnable ", edition, " Edition SMTP Connector, version =>>", ver, "<<\n");
if (edition == "Standard") {
  # nb: see <http://www.mailenable.com/standardhistory.html> for history.
  if (ver =~ "^1\.7") security_warning(port);
}
else if (edition == "Professional") {
  # nb: there were no version 1.3x or 1.4x; see 
  #     <http://www.mailenable.com/professionalhistory.html>.
  if (ver =~ "^1\.(2|5[a-e])") security_warning(port);
}
