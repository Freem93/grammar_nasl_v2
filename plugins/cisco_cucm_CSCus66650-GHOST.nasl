#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81546);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus66650");
  script_xref(name:"CERT", value:"967332");

  script_name(english:"Cisco Unified Communications Manager Remote Buffer Overflow (CSCus66650) (GHOST)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by a heap-based
buffer overflow in the GNU C Library (glibc) due to improperly
validating user-supplied input in the glibc functions
__nss_hostname_digits_dots(), gethostbyname(), and gethostbyname2().
This allows a remote attacker to cause a buffer overflow, resulting in
a denial of service condition or the execution of arbitrary code.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco bug advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
app_name    = "Cisco Unified Communications Manager (CUCM)";

fixed_ver   = FALSE;

# Advisory says 7.1.5 - 10.5.2
if(ver =~ "^7\." &&
   ver_compare(ver:ver, fix:"7.1.5", strict:FALSE) >= 0 &&
   ver_compare(ver:ver, fix:"8.0.0", strict:FALSE) <  0
  )
  fixed_ver = "8.6.1.20013.3";
else if(ver =~ "^8\." && ver_compare(ver:ver, fix:"8.6.1.20013.3", strict:FALSE) < 0)
  fixed_ver = "8.6.1.20013.3";
else if(ver =~ "^8\.6\.2\." && ver_compare(ver:ver, fix:"8.6.2.26158.1", strict:FALSE) < 0)
  fixed_ver = "8.6.2.26158.1";
else if(ver =~ "^10\.0\." && ver_compare(ver:ver, fix:"10.0.1.13015.1",  strict:FALSE) < 0)
  fixed_ver = "10.0.1.13015.1";
else if(ver =~ "^10\.5\." && ver_compare(ver:ver, fix:"10.5.2.11008.1",  strict:FALSE) < 0)
  fixed_ver = "10.5.2.11008.1";
else if(ver =~ "^11\.0\." && ver_compare(ver:ver, fix:"11.0.0.98000.89", strict:FALSE) < 0)
  fixed_ver = "11.0.0.98000.89";
else if(ver =~ "^9\.1\."  && ver_compare(ver:ver, fix:"9.1.2.13078.1",   strict:FALSE) < 0)
  fixed_ver = "9.1.2.13078.1";
else
   audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);


if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus66650'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
