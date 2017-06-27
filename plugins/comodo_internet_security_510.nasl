#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58952);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2012-2273");
  script_bugtraq_id(53163);
  script_osvdb_id(81269);

  script_name(english:"Comodo Internet Security < 5.10 kernel ImageBase Executable Handling Remote DoS");
  script_summary(english:"Checks version of Comodo Internet Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application installed that 
is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Comodo Internet Security installed on the remote 
Windows host is affected by a denial of service vulnerability due to 
the way the application handles specially crafted 32-bit Portable
Executable (PE) files with a kernel ImageBase value.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Apr/138");
  script_set_attribute(attribute:"see_also", value:"http://www.comodo.com/home/download/release-notes.php?p=anti-malware");
  script_set_attribute(attribute:"solution", value:"Upgrade to Comodo Internet Security 5.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("comodo_internet_security_installed.nasl");
  script_require_keys("SMB/Comodo Internet Security/Version", "SMB/Comodo Internet Security/Path");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

version = get_kb_item_or_exit('SMB/Comodo Internet Security/Version');
path = get_kb_item_or_exit('SMB/Comodo Internet Security/Path');

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
if ("Windows 7" >!< productname && arch != 'x64') exit(0, 'Only Windows 7 x64 is affected.');

if (ver_compare(ver:version, fix:'5.10.228257.2253', strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.10.228257.2253\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Comodo Internet Security', version);
