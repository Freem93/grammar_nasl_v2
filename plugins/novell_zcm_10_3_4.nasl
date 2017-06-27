#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58447);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2012-2223");
  script_bugtraq_id(52291);
  script_osvdb_id(79812);

  script_name(english:"Novell ZENworks Configuration Management 10.3 < 10.3.4 Multiple Vulnerabilities");
  script_summary(english:"Checks ZENworks version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected
by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"ZENworks Configuration Management, configuration management
software from Novell, is installed on the remote Windows host.

According to its version, it is affected by several vulnerabilities :

  - An unspecified vulnerability with regards to the HTTP
    TRACE method.

  - An unspecified vulnerability with regards to the xplat
    agent.");

  script_set_attribute(attribute:"solution", value:
"For version 10.3, upgrade to version 10.3.4 or later.  

For version 11.1, contact Novell Support for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7010137");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

# Get details of the ZENworks install.
path = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
ver = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");

# Check whether the installation is vulnerable. A patch has not been
# released for the 11.1 branch, so currently everything there is
# vulnerable.
fix = "10.3.4.13979";
if (
  (ver =~ "^10\.3($|\.)" && ver_compare(ver:ver, fix:fix) < 0) ||
  (ver =~ "^11\.1($|\.)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
  exit(0);
}
else exit(0, "Novell ZENworks Configuration Management version " + ver + " is installed and is not vulnerable.");
