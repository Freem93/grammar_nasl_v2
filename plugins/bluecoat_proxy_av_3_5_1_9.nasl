#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74037);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Blue Coat ProxyAV 3.5.1.1 - 3.5.1.6 Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the version of Blue Coat ProxyAV.");

  script_set_attribute(attribute:"synopsis", value:"The host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the firmware installed
on the remote host is affected by an information disclosure
vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa79");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Blue Coat ProxyAV 3.5.1.9 or later.

Note that the vendor initially released 3.5.1.7 to address this issue,
removed that, and later released 3.5.19.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:bluecoat:proxyav");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_proxy_av_version.nasl");
  script_require_keys("www/bluecoat_proxyav");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_kb_item_or_exit("www/bluecoat_proxyav");
ver = get_kb_item_or_exit("www/bluecoat_proxyav/" + port + "/version");

url = build_url(port:port, qs:"/");

cut_off = "3.5.1.1";
fix = "3.5.1.7";
if (
  # Lower than 3.5.1.1 is not affected
  ver_compare(ver:ver, fix:cut_off, strict:FALSE) < 0 ||
  # Higher than 3.5.1.7 is not affected
  ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0
)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Blue Coat ProxyAV", url, ver);

# Report our findings.
# Earlier patches were pulled due to flaws;
# 3.5.1.9 is the vendor suggested fix.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 3.5.1.9' +
    '\n';
}
security_hole(port:port, extra:report);
