#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(18123);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/19 01:42:51 $");

  script_bugtraq_id(13350);
  script_osvdb_id(15737);

  script_name(english:"MailEnable HTTPMail Service Authorization Header Remote Overflow");
  script_summary(english:"Checks for Authorization Buffer Overflow Vulnerability in MailEnable HTTPMail Service");
 
  script_set_attribute(  attribute:"synopsis",  value:
"A web application on the remote host has a buffer overflow
vulnerability."  );
  script_set_attribute(  attribute:"description",   value:
"The version of MailEnable running on the remote host has a buffer
overflow vulnerability when processing the Authorization field in
the HTTP header.  A remote attacker could exploit this to execute
arbitrary code."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2005/Apr/408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to the latest version of this software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MailEnable Authorization Header Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/25");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
auth = make_array("Authorization", crap(data:"A", length:5));
buf = http_send_recv3(method:"GET", item:'/', add_headers:auth, port:port, exit_on_fail: 1);

if ("HTTP/1.1 401 Access Denied" >!< buf[0])
  exit(0, "Page / is not protected on port "+port+".");
if ("Server: MailEnable-HTTP/5.0" >!< buf[1])
  exit(0, "Server on port "+port+" is not MailEnable-HTTP/5.0.");

auth = make_array("Authorization", crap(data:"A", length:280));
buf = http_send_recv3(method:"GET", item:'/', add_headers:auth, port:port, exit_on_fail: 1);

if (("HTTP/1.1 401 Access Denied" >!< buf[0]) || ("Server: MailEnable-HTTP/5.0" >!< buf[1]))
  security_hole (port);
