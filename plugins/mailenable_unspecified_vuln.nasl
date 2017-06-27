#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(15611);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_bugtraq_id(11578);
  script_osvdb_id(11322);
  script_xref(name:"Secunia", value:"13062");

  script_name(english:"MailEnable Professional Webmail < 1.5.1 Unspecified Vulnerability");
  script_summary(english:"Checks for the version of MailEnable");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote webmail service has an unspecified vulnerability."
  );
  script_set_attribute(  attribute:"description",   value:
"The version of MailEnable Professional hosted on the remote host
has an unspecified vulnerability in the webmail module."  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MailEnable Professional 1.5.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # assumes worst case scenario
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
str = egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner);
if ( ! str ) exit(0);

ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:str, icase:TRUE);
if (ver == NULL || ver[1] == NULL ) exit(1);
ver = ver[2];
if (ver =~ "^1\.(2.*|5)([^.]|$)") security_hole(port);
