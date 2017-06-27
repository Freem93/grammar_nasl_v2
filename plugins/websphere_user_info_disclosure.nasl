#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16173);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2012/01/20 12:24:16 $");

  script_bugtraq_id(11816);
  script_osvdb_id(12185);
  script_xref(name:"Secunia", value:"13234");

  script_name(english:"IBM Websphere Commerce Database Update Information Disclosure");
  script_summary(english:"Detects Websphere default user information leak");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Websphere Commerce that
may allow potentially confidential information to be accessed through
the default user account.  An attacker, exploiting this flaw, would
only need to be able to make standard queries to the application
server.");
  script_set_attribute(attribute:"solution", value:
"Contact WebSphere Commerce support to resolve the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_commerce");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/WebSphere");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner) exit(0);
# Server: WebSphere Application Server/6.0
if (egrep(string:banner, pattern:"^Server: WebSphere Application Server/([0-4]\.|5\.[0-6][^0-9])"))	
   security_note(port);
