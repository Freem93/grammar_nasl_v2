#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27583);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/09/30 21:06:07 $");

  script_cve_id("CVE-2007-4277");
  script_bugtraq_id(26209);
  script_osvdb_id(39755);

  script_name(english:"Trend Micro Scan Engine Tmxpflt.sys Buffer Overflow");
  script_summary(english:"Checks version of AV scan engine");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a local
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro AntiVirus installed on the remote Windows
host contains a buffer overflow in its 'Tmxpflt.sys' kernel driver.  A
local attacker may be able to leverage this issue to execute arbitrary
code on the affected system in kernel context.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d005b51");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482794/30/0/threaded");
  # http://web.archive.org/web/20071028140255/http://esupport.trendmicro.com/support/viewxml.do?ContentID=1036190
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?716206ce");
  # http://web.archive.org/web/20071028140249/http://esupport.trendmicro.com/support/viewxml.do?ContentID=1035793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff991f13");
  script_set_attribute(attribute:"solution", value:"Update to Scan Engine 8.550-1001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119,264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:pc-cillin_internet_security_2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:scan_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/installed", "Antivirus/TrendMicro/trendmicro_engine_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

engine = get_kb_item_or_exit("Antivirus/TrendMicro/trendmicro_engine_version");

ver = split(engine, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 8 || 
  (ver[0] == 8 && ver[1] < 550)
)
{
  if (report_verbosity > 0)
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;

    report = '\n  Current engine version : ' + engine +
             '\n  Fixed engine version   : 8.550' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The remote host has engine version "+engine+" and thus is not affected.");
