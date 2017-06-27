#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93222);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_bugtraq_id(71624);
  script_osvdb_id(115649);

  script_name(english:"MiniUPnP DNS Rebind Vulnerability");
  script_summary(english:"Sends an HTTP GET request to the server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a DNS rebind vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MiniUPnP that is affected by
an unspecified flaw that exists in the Domain Name System (DNS)
related to the 'rebinding' interaction. An unauthenticated, remote
attacker can exploit this, by convincing a user to visit a specially
crafted web page, to run a client-side script that interacts with the
systems on their network.");
  # http://miniupnp.free.fr/files/changelog.php?file=miniupnpd-1.9.20141209.tar.gz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7516605f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MiniUPnP version 1.9 or later. Alternatively, if the
remote target is an embedded device, disable UPnP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:miniupnp_project:miniupnpd");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_igd.nasl");
  script_require_ports("upnp/www");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

appname = 'MiniUPnPd';

port = get_kb_item_or_exit("upnp/www");
# Since a DNS rebind attack is only useful against a device with a
# globally routable ip, we will restrict this script to upnp devices
# that have IGD implemented (ie routers). That should avoid flagging
# devices that are vulnerable but are not practically exploitable.
get_kb_item_or_exit("upnp/"+port+"/www/igd");
banner = get_kb_item_or_exit('upnp/' + port + '/www/banner');

# if this isn't miniupnpd then don't go on
ver = eregmatch(string:banner, pattern:'miniupnpd/([0-9.]+)', icase:TRUE);
if (isnull(ver)) audit(AUDIT_WRONG_WEB_SERVER, port, appname);

# get the location. We will need to do a successful request to verify the evil request
url_split = split_url(url:get_kb_item_or_exit('upnp/'+port+'/location'));
if (isnull(url_split)) exit(1, "The M-SEARCH response did not contain a valid location field.");

# only continue if we are certain this points at our target
if (get_host_ip() != url_split["host"]) exit(1, "The host location does not point to the target IP");

# this should be a good request
resp = http_send_recv3(method:"GET",
                       port:url_split["port"],
                       item:url_split["page"],
                       host:get_host_ip(),
                       exit_on_fail:TRUE);

if (isnull(resp) || '200 OK' >!< resp[0]) audit(AUDIT_RESP_BAD, port, "an HTTP request.");

# if this request is successful than a DNS rebind attack is possible. See:
# https://github.com/miniupnp/miniupnp/commit/98cc73a372d61988b252794340daff68e2304a9d
hostname = 'tenable.com';
resp = http_send_recv3(method:"GET",
                       port:url_split["port"],
                       item:url_split["page"],
                       host:hostname,
                       exit_on_fail:TRUE);

if (!isnull(resp) && '200 OK' >< resp[0])
{
  report = 'The server did not reject an HTTP request with the host field of ' + hostname + '\n' +
           'Which means this server is vulnerable to a DNS rebind attack';
  security_report_v4(port:port,
                     severity:SECURITY_WARNING,
                     extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port);
