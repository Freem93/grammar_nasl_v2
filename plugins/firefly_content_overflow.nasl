#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32031);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-1771");
  script_bugtraq_id(28860);
  script_osvdb_id(44448);

  script_name(english:"Firefly Media Server ws_getpostvars Function Content-Length Header HTTP Request Handling Overflow");
  script_summary(english:"Sends a specially crafted POST request header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an integer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Firefly Media Server, also known as
mt-daapd, a media streaming server. 

The version of Firefly Media Server installed on the remote host
apparently fails to sanitize user-supplied Content-Length field
before using it to the call to 'malloc(len+1)' in 'src/webserver.c'. 
Using a specially crafted HTTP POST content-length request header, an
unauthenticated, remote attacker can leverage this issue to crash the
affected service or to execute arbitrary code on the affected system,
subject to the privileges under which the service operates." );
  # http://sourceforge.net/project/shownotes.php?release_id=593465&group_id=98211
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4f1db9e" );
 script_set_attribute(attribute:"solution", value:
"Either disable the service or upgrade to Firefly Media Server 0.2.4.2
or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/23");
 script_cvs_date("$Date: 2016/05/05 16:01:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:fireflymediaserver:fireflymediaserver");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
w = http_send_recv3(method:"POST", item: "/", version: 10, port: port,
  add_headers: make_array("Content-Length", "-1"));
if (isnull(w)) exit(1, "The web server did not answer");

res = strcat(w[0], w[1], '\r\n', w[2]);

# there's a problem if we see a response with an invalid argument error.
if (!isnull(res) && "<br>Error: Invalid argument" >< res)
  security_hole(port);

