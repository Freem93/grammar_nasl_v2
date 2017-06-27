#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100130);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2016-8008", "CVE-2016-8026");
  script_bugtraq_id(98068);
  script_osvdb_id(150794, 150795);
  script_xref(name:"IAVB", value:"2017-B-0054");

  script_name(english:"McAfee Security Scan Plus < 3.11.474.2 Multiple Vulnerabilities (TS102593 / TS102614)");
  script_summary(english:"Checks the version of McAfee Security Scan Plus.");

  script_set_attribute(attribute:"synopsis", value:
"The security application installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Security Scan Plus installed on the remote
Windows host is prior to 3.11.474.2. It is, therefore, affected by
multiple vulnerabilities :

  - A privilege escalation vulnerability exists in
    McUICnt.exe due to certain DLL files being loaded from
    the same directory as signed binaries that are scanned
    using a class object from
    McComponentHostService.McCompHost. A local attacker can
    exploit this to gain SYSTEM privileges. (CVE-2016-8008)

  - A local command execution vulnerability exists in the
    internal API due to a flaw that allows programs to be
    executed using the RunProgramEx() function in an class
    object loaded from McComponentHostService.McCompHost. A
    local attacker can exploit this to execute commands with
    SYSTEM privileges. (CVE-2016-8026)");
  # https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102593
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ed69847");
  # https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102614
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5a3ba9d");
  # https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2017-002/?fid=8900
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?575d7572");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Security Scan Plus version 3.11.474.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:security_scan_plus");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_ssp_installed.nbin");
  script_require_keys("installed_sw/McAfee Security Scan Plus");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"McAfee Security Scan Plus", win_local:TRUE);

constraints = [{ "fixed_version" : "3.11.474.2" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
