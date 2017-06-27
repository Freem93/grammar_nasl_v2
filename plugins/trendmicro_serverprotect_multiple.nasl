#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24680);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/01/15 16:41:31 $");

  script_cve_id("CVE-2007-1070");
  script_bugtraq_id(22639);
  script_osvdb_id(33042);

  script_name(english:"Trend Micro ServerProtect TmRpcSrv.dll RPC Request Multiple Overflows");
  script_summary(english:"Checks for ServerProtect version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the
AntiVirus Agent.");
  script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to
multiple stack overflows in the RPC interface. By sending specially
crafted requests to the remote host, an attacker may be able to
exploit stack based overflows and execute arbitrary code on the remote
host.");
  # http://web.archive.org/web/20081023005716/http://dvlabs.tippingpoint.com/advisory/TPTI-07-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0afdbfea");
  # http://web.archive.org/web/20080820001307/http://dvlabs.tippingpoint.com/advisory/TPTI-07-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6212c055" );
  script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/download/product.asp?productid=17");
  script_set_attribute(attribute:"solution", value:
"Trend Micro has released a patch for ServerProtect for
Windows / NetWare.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-206");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Trend Micro ServerProtect 5.58 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:serverprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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
  (v[0] == 5 && v[1] == 58 && v[2] == 0 && v[3] < 1171)
) 
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version + 
             '\n  Fixed version     ; 5.58.0.1171' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit("The Trend Micro ServerProtect install is not affected.");
