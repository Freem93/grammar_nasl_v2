#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10154);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2014/05/26 01:40:12 $");

  script_cve_id("CVE-1999-0751");
  script_bugtraq_id(631);
  script_osvdb_id(120);

  script_name(english:"Netscape Enterprise Server Accept Header Remote Overflow");
  script_summary(english:"Attmept overflow with large Accept value.");

   script_set_attribute(attribute:"synopsis", value:"The remote service is prone to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The remote web server seems to crash when it is issued a too long
argument to the 'Accept:' command :

Example :

 GET / HTTP/1.0 Accept: <thousands of chars>/gif

This may allow an attacker to execute arbitrary code on the remote
system.");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of Netscape Enterprise Server greater than 3.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/09/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:enterprise_server");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl");
  script_require_keys("www/iplanet", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port:port))exit(0);


w = http_send_recv3(method:"GET", item: "/", port: port,
  add_headers: make_array("Accept", crap(2000)+"/gif"));

if (isnull(w)) security_warning(port);
