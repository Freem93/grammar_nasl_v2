#
# (C) Tenable Network Security, Inc.
#

# The following HTTP requests have been provided as examples by
# David Litchfield (david@nextgenss.com):
#
# GET / HTTP/1.1
# Host: iis-server
# Authorization: Basic cTFraTk6ZDA5a2xt

# GET / HTTP/1.1
# Host: iis-server
# Authorization: Negotiate TlRMTVNTUAABAAAAB4IAoAAAAAAAAAAAAAAAAAAAAAA=

include("compat.inc");

if (description)
{
  script_id(11871);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2002-0419");
  script_bugtraq_id(4235);
  script_osvdb_id(13426);

  script_name(english:"Microsoft IIS Authentication Method Enumeration");
  script_summary(english:"Find IIS authentication scheme");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of IIS which allows
remote users to determine which authentication schemes are required for
confidential web pages.

That is, by requesting valid web pages with purposely invalid
credentials, you can ascertain whether or not the authentication scheme
is in use.  This can be used for brute-force attacks against known
USerIDs.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq;m=101535399100534;w=2");
  script_set_attribute(attribute:"solution", value:
"If the application allows, disable any authentication methods that are
not used in the IIS Properties interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/iis", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80, embedded: 0);

b = get_http_banner(port: port, exit_on_fail: 1);
if ("IIS" >!< b )
 exit(0, "The web server on port "+port+" is not IIS.");

rq = strcat('GET / HTTP/1.1\r\nHost: ', get_host_name(), '\r\n');

w = http_send_recv_buf(port: port, data: rq, exit_on_fail: 1);
if (w[0] =~ "401 Unauthorized") exit(1, "/ is protected on port "+port+".");

auth[0] = "- IIS Basic authentication";
auth[1] = "- IIS NTLM authentication";
req[0] = strcat(rq, 'Authorization: Basic cTFraTk6ZDA5a2xt\r\n\r\n');
req[1] = strcat(rq, 'Authorization: Negotiate TlRMTVNTUAABAAAAB4IAoAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n');
flag=0;

mywarning = string(
  "\n",
  "The following authentication methods are enabled on the remote\n",
  "webserver.\n"
);

for (i=0; req[i]; i++) {
  w = http_send_recv_buf(data:req[i], port:port, exit_on_fail: 1);

  if (w[0] =~ "401 Unauthorized")
  {
    mywarning = mywarning + auth[i];
    flag++;
  }
}

if (flag)
 security_note(port:port, extra:mywarning);
else
 exit(0, "The web server on port "+port+" is unaffected.");
