#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63684);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2012-1508", 
    "CVE-2012-1509", 
    "CVE-2012-1510", 
    "CVE-2012-1511"
  );
  script_bugtraq_id(52524, 52526);
  script_osvdb_id(80115, 80116, 80117, 80118); 
  script_xref(name:"VMSA", value:"2012-0004");

  script_name(english:"VMware View Multiple Vulnerabilities (VMSA-2012-0004)");
  script_summary(english:"Checks VMware View version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtual desktop solution that is potentially 
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The VMware View, formerly VMware Virtual Desktop Infrastructure  
components (Agent or Server), on the remote host is 4.x prior to 
4.6.1.  It is, therefore, potentially affected by the following 
vulnerabilities :

  - A buffer overflow vulnerability exists in the XPDM and 
    WDDM display drivers and a NULL pointer dereference in 
    WDDM display driver that could allow local attackers to 
    elevate privileges and potentially execute arbitrary 
    code. (CVE-2012-1508, CVE-2012-1509, CVE-2012-1510)

  - A cross-site scripting vulnerability exists where input 
    passed via view manager portal is not properly validated. 
    A remote attacker could exploit this vulnerability by 
    creating a specially crafted URL, which could result in 
    execution of arbitrary script code. (CVE-2012-1511)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0004.html");
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to VMware View Server 4.6.1 / VMware View Agent 4.6.1 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_view_server_detect.nasl", "vmware_view_agent_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

fix = '4.6.1';
report = "";
port = kb_smb_transport();

server_installed = get_kb_item("VMware/ViewServer/Installed");
version = get_kb_item("VMware/ViewServer/Version");
path = get_kb_item("VMware/ViewServer/Path");
if (!isnull(server_installed))
{
  appname = 'VMware View Server';
  if(version =~ '^4\\.[0-6]' && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    set_kb_item(name:"www/0/XSS", value:TRUE);
    report +=
      '\n  Product           : ' + appname + 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version+
      '\n  Fixed version     : ' + fix + '\n';
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
}

appname = 'VMware View Agent';
agent_installed = get_kb_item("VMware/ViewAgent/Installed");
version = get_kb_item("VMware/ViewAgent/Version");
path = get_kb_item("VMware/ViewAgent/Path");
 
if (!isnull(agent_installed)) 
{
  if (version =~ '^4\\.[0-6]' && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    report +=
      '\n  Product           : ' + appname + 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version+
      '\n  Fixed version     : ' + fix + '\n';
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
}

if (agent_installed == FALSE && server_installed == FALSE)  audit(AUDIT_NOT_INST, "VMware View Server / VMware View Agent");

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port:port);
