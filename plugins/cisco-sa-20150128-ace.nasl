#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81423);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus68907");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus67782");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");
  script_xref(name:"CERT", value:"967332");

  script_name(english:"Cisco Application Control Engine GNU glibc gethostbyname Function Buffer Overflow Vulnerability (cisco-sa-20150128-ghost) (GHOST)");
  script_summary(english:"Checks the ACE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco Application Control Engine (ACE) software installed on the
remote Cisco IOS device is version A2(3.6d) or A5(3.1b). It is,
therefore, affected by a heap-based buffer overflow vulnerability in
the GNU C Library (glibc) due to improperly validating user-supplied
input to the __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2() functions. This allows a remote attacker to cause a
buffer overflow, resulting in a denial of service condition or the
execution of arbitrary code.");
  # http://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20150128-ghost.html#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bcef63c");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus68907");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus67782");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"The vendor has stated that no release is planned to fix this issue.
Contact the vendor for other possible options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  # Vendor states remote-trigger is not possible

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco ACE');

if (
  version == "A2(3.6d)" ||
  version == "A5(3.1b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : See solution.' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
