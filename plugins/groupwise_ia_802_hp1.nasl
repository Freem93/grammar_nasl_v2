#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50692);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/10 15:57:06 $");

  script_cve_id(
    "CVE-2010-4326",
    "CVE-2010-4711",
    "CVE-2010-4712",
    "CVE-2010-4713",
    "CVE-2010-4714",
    "CVE-2010-4717"
  ); 
  script_bugtraq_id(44732, 45994);
  script_osvdb_id(69139, 69142, 69140, 69141, 69143);
  script_xref(name:"Secunia", value:"40820");

  script_name(english:"GroupWise Internet Agent < 8.0.2 HP1 Multiple Flaws");
  script_summary(english:"Checks GWIA version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GroupWise Internet Agent installed on the remote host
is older than 8.0.2.11941 and hence affected by the following issues :

  - Multiple 'Content-Type' header parsing issues can result
    in arbitrary code execution on the remote system.
    (ZDI-10-237 / ZDI-10-238 / ZDI-10-241)

  - Multiple issues while parsing 'VCALENDAR' data within an
    email message can allow arbitrary code execution on the
    remote system. (ZDI-10-239 / ZDI-10-243 / ZDI-11-025)

  - The IMAP component fails to correctly handle 'IMAP LIST'
    command and can allow an attacker to execute arbitrary
    code on the remote system. (ZDI-10-242)

  - Insufficient validation of HTTP headers could allow 
    arbitrary code execution on the remote system.
    (ZDI-10-247)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-237/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-238/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-239/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-240/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-242/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-243/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-247/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-025");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/442");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007151");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007152");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007153");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007155");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007154");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007157");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007159");

  script_set_attribute(attribute:"solution", value:
"Apply 8.0.2 Hot Patch 1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell GroupWise 8 WebAccess File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl", "groupwise_ia_detect.nasl");
  script_require_keys("SMB/GWIA/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

if (report_paranoia < 2)
{   
  services = get_kb_item_or_exit("SMB/svcs");
  if("GWIA" >!< services) exit(0, "The GWIA service is not running.");
}

version = get_kb_item_or_exit("SMB/GWIA/Version");

path = get_kb_item("SMB/GWIA/Path");
if (isnull(path)) path = "n/a";

# Check the version number.
if (ver_compare(ver:version, fix:'8.0.2.11941') == -1) 
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.2.11941\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0,"GroupWise Internet Agent version "+ version + " is installed and hence is not affected.");
