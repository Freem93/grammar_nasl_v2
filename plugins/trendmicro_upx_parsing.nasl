#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24681);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2007-0851");
  script_bugtraq_id(22449);
  script_osvdb_id(33038);
  script_xref(name:"CERT", value:"276432");
  script_xref(name:"IAVA", value:"2007-A-0013");

  script_name(english:"Trend Micro UPX File Parsing Overflow");
  script_summary(english:"Checks if Trend Micro Antivirus virus pattern file is vulnerable"); 

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is vulnerable to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Trend Antivirus, a commercial antivirus
software package for Windows.  The scan engine of the remote antivirus
is affected by a UPX file parsing vulnerability that could potentially
allow an attacker to crash the scan engine or execute arbitrary code.");
  script_set_attribute(attribute:"solution", value:
"Upgrade virus pattern file to 4.245.00 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=470
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbca8d4a");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/32352");

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/21");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/08");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:trend_micro_antivirus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");

pattern_ver = get_kb_item("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
good_pattern_ver = 424500;

# - check if virus pattern file is vulnerable?

trouble = 0;
if (!isnull(pattern_ver))
{
    if ( int(pattern_ver) < int(good_pattern_ver))
    {
      info += 'The virus pattern file ' + pattern_ver + ' on the remote host is vulnerable to the above flaw,' +
              ' please upgrade to ' + good_pattern_ver + ' or higher.\n';
      trouble++;
    }
}

if (trouble)
{
  security_hole(port:get_kb_item("SMB/transport"), extra:'\n'+info);
}
