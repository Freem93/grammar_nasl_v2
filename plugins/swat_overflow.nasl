#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(13660);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2004-0600");
  script_bugtraq_id(10780);
  script_osvdb_id(8190);

  script_name(english:"Samba SWAT HTTP Basic Auth base64 Overflow");
  script_summary(english:"SWAT overflow");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SWAT - a web-based administration tool for
Samba.

There is a buffer overflow condition in the remote version of this
software which might allow an attacker to execute arbitrary code on
the remote host by sending a malformed authorization request (or any
malformed base64 data).");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/261");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/268");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/270");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK); # Or ACT_ATTACK ? Swat is started from inetd after all...
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("swat_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/swat", 901);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc: "swat", default: 901, exit_on_fail: 1);

w = http_send_recv3(method: "GET", port: port, item: "/",
  username: "", password: "", exit_on_fail: 1,
  add_headers: make_array("Authorization", "Basic aaa="));

res = strcat(w[0], w[1], '\r\n', w[2]);
if ('realm="SWAT"' >!< res ) exit(0);

w = http_send_recv3(method:"GET", port: port, item: "/",
  username: "", password: "", exit_on_fail: 0,
  add_headers: make_array("Authorization", "Basic ="));

if (isnull(w)) security_hole(port);
