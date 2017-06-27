#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85449);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69785");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");
  script_xref(name:"CERT", value:"967332");

  script_name(english:"Cisco Unified Communications Manager IM and Presence GNU C Library (glibc) Buffer Overflow (CSCus69785) (GHOST)");
  script_summary(english:"Checks the CUPS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager IM and Presence Server Service is affected by a
heap-based buffer overflow condition in the GNU C Library (glibc) due
to improper validation of user-supplied input to the glibc functions
__nss_hostname_digits_dots(), gethostbyname(), and gethostbyname2().
This allows a remote attacker to cause a buffer overflow, resulting in
a denial of service condition or the execution of arbitrary code.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69785");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco bug ID CSCus69785.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl","cisco_unified_detect.nasl");
  script_require_ports("Host/UCOS/Cisco Unified Presence/version",'cisco_cups/system_version');

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

# Leverage SSH version first
display_version = get_kb_item("cisco_cups/system_version");
ver = display_version;
# Fall back to API
if (isnull(display_version))
{
  display_version = get_kb_item_or_exit('Host/UCOS/Cisco Unified Presence/version');
  match = eregmatch(string:display_version, pattern:"^(\d+\.\d+\.\d+\.\d+-\d+)($|[^0-9])");
  if (isnull(match)) 
    audit(AUDIT_VER_FORMAT, display_version); 
  ver = match[1];
}

ver = str_replace(string:ver, find:"-", replace:".");
# 7.0 - 11.0 (11 not yet released)
if(ver_compare(ver:ver, fix:"7.0",           strict:FALSE) >= 0 &&
   ver_compare(ver:ver, fix:"8.6.5.15900.3", strict:FALSE) <  0)
  fixed_ver = "8.6.5 SU5 (8.6.5.15900-3)";
else if(ver =~ "^9\."  && ver_compare(ver:ver, fix:"9.1.1.71900.2",   strict:FALSE) < 0)
  fixed_ver = "9.1.1 SU5 (9.1.1.71900-2)";
else if(ver =~ "^10\.[0-4]\.")
  fixed_ver = "10.5.1 SU3 (10.5.1.13900-2)"; # Any version of 10 prior to 10.5 go to 10.5.1
else if(ver =~ "^10\.5\.1\." && ver_compare(ver:ver, fix:"10.5.1.13900.2", strict:FALSE) < 0)
  fixed_ver = "10.5.1 SU3 (10.5.1.13900-2)";
else if(ver =~ "^10\.5\.2\." && ver_compare(ver:ver, fix:"10.5.2.21900.2", strict:FALSE) < 0)
  fixed_ver = "10.5.2b (10.5.2.21900-2)";
else if(ver =~ "^11\.0\." &&  ver_compare(ver:ver, fix:"11.0.1.10000.6", strict:FALSE) < 0)
  fixed_ver = "11.0.1.10000-6";
else
   audit(AUDIT_INST_VER_NOT_VULN, "CUCM IM and Presence Service", display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
