#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24815);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-1591");
  script_bugtraq_id(22965);
  script_osvdb_id(34075);

  script_name(english:"Trend Micro VsapiNT.sys UPX File Parsing DoS");
  script_summary(english:"Checks version of virus pattern file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Trend Micro Antivirus installed on the remote Windows
host contains a divide-by-zero error in its 'VsapiNT.sys' kernel
driver.  Using a specially crafted UPX file, a remote attacker may be
able to leverage this flaw to crash the affected host." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=488
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085d4ea4" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/462798/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/id?1017768" );
 script_set_attribute(attribute:"solution", value:
"Update the Virus Pattern File to 4.335.00 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/03/14");
 script_cvs_date("$Date: 2013/04/25 21:51:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:trend_micro_antivirus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");

pats = get_kb_item("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
if (!isnull(pats) && int(pats) < 433500)
{
  report = string(
    "\n",
    "Nessus has determined that the current Virus Pattern File on the remote\n",
    "host is version ", pats, ".\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
