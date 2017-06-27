#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59798);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2012-2942");
  script_bugtraq_id(53647);
  script_osvdb_id(82092);

  script_name(english:"HAProxy Trash Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of HAProxy");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a load balancer with a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Based on the self-reported version obtained from the HAProxy
statistics reporting page, the remote host is running load balancing
software that is potentially affected by a buffer overflow
vulnerability when copying data into the trash buffer.

It may be possible for an attacker to exploit this vulnerability to
execute arbitrary code on the remote host, but it requires that the
global.tune.bufsize option is set to a value greater than default and
that header rewriting is configured."
  );
  script_set_attribute(attribute:"see_also",value:"http://haproxy.1wt.eu/download/1.4/src/CHANGELOG");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to HAProxy version 1.4.21 or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/05/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/06/29");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:haproxy:haproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("haproxy_statspage_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/haproxy_stats_page", "Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

appname = 'HAProxy';
install = get_install_from_kb(appname:'haproxy_stats_page', port:port);
if (isnull(install)) 
  audit(AUDIT_NOT_DETECT, appname, port);

# os packages are available and patches could be backported
if (report_paranoia<2) 
  audit(AUDIT_PARANOID);

dir = install['dir'];
version = install['ver'];

item = eregmatch(pattern:"([0-9\.]+)", string: version);
if(isnull(item[1]))
  exit(1, "Unable to parse version information.");

ver = split(item[1], sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(max_index(ver) < 2)
  exit(1, "HAProxy version information is not granular enough to make a determination.");

vuln = FALSE;

# Versions < 1.4.21 are affected.

if (ver[0] < 1 ||
   (ver[0] == 1 && ver [1] < 4))
  vuln = TRUE;

if(ver[0] == 1 && ver[1] == 4)
{
  if(max_index(ver) < 3)
  {
    if(version =~ "^1\.4-dev[0-8]" || version =~ "^1\.4-rc1")
      vuln = TRUE;
    else
      exit(1, "Unrecognized HAProxy version.");
  } 
  else if(ver[2] < 21)
    vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
    '\n  URL               : ' + build_url(port:port, qs:dir) +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 1.4.21\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
