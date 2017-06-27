#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81407);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69523");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco TelePresence Conductor GNU glibc gethostbyname Function Buffer Overflow Vulnerability (GHOST)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco TelePresence Conductor device is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco TelePresence
Conductor remote device is affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validating user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69523");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.4 / 3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_conductor");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_conductor_detect.nbin");
  script_require_keys("Host/Cisco_TelePresence_Conductor/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod = "Cisco TelePresence Conductor";
version = get_kb_item_or_exit("Host/Cisco_TelePresence_Conductor/Version");

if (
  version =~ "^1(\.|$)" ||
  (version =~ "^2\.[0-3](\.|$)")
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed versions    : 2.4 / 3.0' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
