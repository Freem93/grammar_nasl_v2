#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69930);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2010-5191");
  script_bugtraq_id(44385);
  script_osvdb_id(68879);

  script_name(english:"Blue Coat ProxyAV < 3.2.6.1 Multiple Admin Function CSRF");
  script_summary(english:"Checks the version of Blue Coat ProxyAV.");

  script_set_attribute(attribute:"synopsis", value:
"The host is affected by multiple admin function cross-site request
forgery vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the firmware installed
on the remote host is affected by multiple admin function cross-site
request forgery vulnerabilities. 

Note that Nessus has not tested for the issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=SA46");
  script_set_attribute(attribute:"solution", value:"Upgrade to Blue Coat ProxyAV 3.2.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:bluecoat:proxyav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_proxy_av_version.nasl");
  script_require_keys("Settings/ParanoidReport", "www/bluecoat_proxyav");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_kb_item_or_exit("www/bluecoat_proxyav");
ver = get_kb_item_or_exit("www/bluecoat_proxyav/" + port + "/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

url = build_url(port:port, qs:"/");

fix = "3.2.6.1";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Blue Coat ProxyAV", url, ver);

set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
