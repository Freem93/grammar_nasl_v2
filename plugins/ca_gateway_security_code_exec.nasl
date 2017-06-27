#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55692);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2011-2667");
  script_bugtraq_id(48813);
  script_osvdb_id(74119);
  script_xref(name:"Secunia", value:"45332");

  script_name(english:"CA Gateway Security Malformed HTTP Packet Remote Code Execution");
  script_summary(english:"Checks version of CA Gateway Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a security application that is 
affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the CA Gateway Security install on
the remote Windows host is affected by a code execution vulnerability
caused by a heap corruption condition when handling specially crafted
HTTP requests on port 8080. 

A remote, unauthenticated attacker could exploit this flaw and execute
arbitrary code on the host subject to the privileges of the user
running the affected application.");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-237");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jul/128");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d309d2b");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dfd61d0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CA Gateway Security 9.0 or later, or apply the fix
referenced in the advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:etrust_antivirus_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ca_gateway_security_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/CA Gateway Security/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

path = get_kb_item_or_exit('SMB/CA Gateway Security/Path');
version = get_kb_item_or_exit('SMB/CA Gateway Security/Version');

# Unless we're paranoid, make sure the service is running
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/eTrust AntiVirus Gateway HTTP');
  if (status != SERVICE_ACTIVE)
    exit(0, 'The Antivirus Gateway HTTP service is installed but not active.');
}

fixed_version = '8.1.0.69';

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version       : ' + version +
      '\n  Fixed version : 8.1.0.69 / 9.0\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(port:get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'CA Gateway Security version '+version+' is installed, and thus is not affected.');
