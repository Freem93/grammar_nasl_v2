#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25925);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2007-4218", "CVE-2007-4219", "CVE-2007-4731");
  script_bugtraq_id(25395, 25396, 25595);
  script_osvdb_id(39750, 39751, 39752, 39753, 39754, 45878);

  script_name(english:"Trend Micro ServerProtect Multiple Remote Overflows");
  script_summary(english:"Checks for ServerProtect version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the
AntiVirus Agent.");
  script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to
multiple buffer overflows in the RPC interface. By sending specially
crafted requests to the remote host, an attacker may be able to
exploit those overflows and execute arbitrary code on the remote host
with SYSTEM privileges.");
  # http://www.trendmicro.com/ftp/documentation/readme/spnt_558_win_en_securitypatch3_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad66593b");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=588
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e9da692" );
  script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/download/product.asp?productid=17");
  script_set_attribute(attribute:"solution", value:
"Trend Micro has released a patch for ServerProtect for
Windows / NetWare.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-229");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:serverprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies ("trendmicro_serverprotect_detect.nasl");
  script_require_keys ("Antivirus/TrendMicro/ServerProtect");
  script_require_ports(5168);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/TrendMicro/ServerProtect");

port = 5168;

v = split (version, sep:".", keep:FALSE);

if (
  (v[0] < 5) ||
  (v[0] == 5 && v[1] < 58) ||
  (v[0] == 5 && v[1] == 58 && v[2] == 0 && v[3] < 1185) 
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version + 
             '\n  Fixed version     ; 5.58.0.1185' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit("The Trend Micro ServerProtect install is not affected.");

