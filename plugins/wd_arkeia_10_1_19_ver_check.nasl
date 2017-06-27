#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74262);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2014-0160", "CVE-2014-2846");
  script_bugtraq_id(66690, 67039);
  script_osvdb_id(105465, 106167);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"EDB-ID", value:"33005");

  script_name(english:"Western Digital Arkeia 10.1.x < 10.1.19 / 10.2.x < 10.2.9 Multiple Vulnerabilities (Heartbleed)");
  script_summary(english:"Checks version of Western Digital Arkeia.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a virtual appliance that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported version of the remote Western Digital Arkeia device
is prior to 10.1.19 / 10.2.9. It is, therefore, potentially affected
by the following vulnerabilities :

 - An out-of-bounds read error, known as the 'Heartbleed
   Bug', exists related to handling TLS heartbeat
   extensions that could allow an attacker to obtain
   sensitive information such as primary key material,
   secondary key material, and other protected content.
   (CVE-2014-0160)

 - A local file inclusion vulnerability exists. A remote,
   unauthenticated attacker can exploit this issue to read
   or execute arbitrary files by crafting a request with
   directory traversal sequences in the 'lang' HTTP cookie.
   (CVE-2014-2846)");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140423-0_WD_Arkeia_Path_Traversal_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b88cb2");
  script_set_attribute(attribute:"see_also", value:"http://wiki.arkeia.com/index.php/Path_Traversal_Remote_Code_Execution");
  script_set_attribute(attribute:"see_also", value:"http://www.wdc.com/en/heartbleedupdate/");
  # ftp://ftp.arkeia.com/arkeia-software-application/arkeia-10.1/documentation/CHANGES-10.1.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b286eb09");
  # ftp://ftp.arkeia.com/arkeia-software-application/arkeia-10.2/documentation/CHANGES-10.2.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97c1883b");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 10.1.19 / 10.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wdc:arkeia_virtual_appliance");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("wd_arkeia_detect.nbin");
  script_require_keys("www/PHP", "www/wd_arkeia");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:TRUE);

app = "Western Digital Arkeia";

install = get_install_from_kb(
  appname      : "wd_arkeia",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
version = install["ver"];
install_url = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 10.1.19 / 10.2.9 are affected
if (
  (ver[0] < 10) ||
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 19) ||
  (ver[0] == 10 && ver[1] == 2 && ver[2] < 9)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.1.19 / 10.2.9' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
