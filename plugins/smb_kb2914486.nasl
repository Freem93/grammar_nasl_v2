#
# (C) Tenable Network Security, Inc.
#

#@DEPRECATED@
#
# Disabled on 2014/01/14.  Deprecated by smb_nt_ms14-002.nasl

include("compat.inc");

if (description)
{
  script_id(71140);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/01/19 03:40:57 $");

  script_cve_id("CVE-2013-5065");
  script_bugtraq_id(63971);
  script_osvdb_id(100368);
  script_xref(name:"EDB-ID", value:"30014");
  script_xref(name:"IAVA", value:"2014-A-0004");

  script_name(english:"KB2914486: Vulnerability in Microsoft Windows Kernel Could Allow Elevation of Privilege");
  script_summary(english:"Checks if NDProxy.sys has been disabled.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a privilege elevation vulnerability in a
system-provided communications driver."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an unspecified privilege elevation vulnerability
in NDProxy.sys, a system-provided communications driver. Successful
exploitation of this vulnerability could allow an attacker to run
arbitrary code in kernel mode. Additionally, the attacker could view,
change or even delete data, as well as install programs and/or create
new accounts with full administrative rights."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2914486");
  # http://www.fireeye.com/blog/technical/cyber-exploits/2013/11/ms-windows-local-privilege-escalation-zero-day-in-the-wild.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?372a0377");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the workaround referenced in Microsoft Security Advisory
(2914486).  This workaround will cause certain services that rely on
Windows Telephony Application Programming Interfaces (TAPI) to not
function.  Refer to the advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows ndproxy.sys Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_nt_ms14-002.nasl (plugin ID 71942) instead.");

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:"3", win2003:"2") <= 0) audit(AUDIT_OS_SP_NOT_VULN);

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SYSTEM\CurrentControlSet\Services\NDProxy\ImagePath";

imagepath = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
close_registry();

if ("system32\drivers\null.sys" >!< imagepath)
{
  if (report_verbosity > 0)
  {
    report = '\n  NDProxy.sys has not been modified by the workaround.\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "NDProxy.sys");
