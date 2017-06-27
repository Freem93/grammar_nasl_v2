#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51815);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/10 15:57:06 $");
  
  script_cve_id("CVE-2010-4325");
  script_bugtraq_id(46025);
  script_osvdb_id(70676);
  script_xref(name:"Secunia", value:"43089");

  script_name(english:"GroupWise Internet Agent < 8.0.2 HP2 Email Message VCALENDAR Data TZID Variable Remote Overflow");
  script_summary(english:"Checks GWIA version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GroupWise Internet Agent installed on the remote host
is older than 8.0.2.12377 and hence reportedly affected by an buffer
overflow vulnerability.  The installed version fails to correctly
parse 'VCALENDAR' data within an email message containing a specially
crafted 'TZID' variable value.  

Successful exploitation of this issue could result in arbitrary code
execution on the remote system with SYSTEM privileges. 
(ZDI-11-027)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-027/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/488");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007638");

  script_set_attribute(attribute:"solution", value:
"Update GWIA to version 8.0.2 Hot Patch 2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/25"); # date patch was available for download.
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "groupwise_ia_detect.nasl");
  script_require_keys("SMB/GWIA/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
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
if (ver_compare(ver:version, fix:'8.0.2.12377') == -1) 
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.2.12377\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0,"GroupWise Internet Agent version "+ version + " is installed and hence is not affected.");
