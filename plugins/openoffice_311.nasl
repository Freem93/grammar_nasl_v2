#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40826);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_bugtraq_id(36200);
  script_osvdb_id(57658, 57659);
  script_xref(name:"Secunia", value:"35036");

  script_name(english:"OpenOffice < 3.1.1 Multiple Buffer Overflows");
  script_summary(english:"Checks version of OpenOffice"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program affected by multiple buffer
overflows." );

  script_set_attribute(attribute:"description", value:
"The version of OpenOffice installed on the remote host is earlier
than 3.1.1. Such versions are affected by several issues :

  - Parsing certain records in a document table could lead
    to heap-based overflows and arbitrary code execution.        
    (CVE-2009-0200)

  - Parsing certain records in specially crafted files could
    lead to heap-based overflows and arbitrary code 
    execution. (CVE-2009-0201)");

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-26" );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-27" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 3.1.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/01");

 script_cvs_date("$Date: 2016/12/07 20:46:54 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}


build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid < 9420) 
      security_hole(get_kb_item("SMB/transport"));
    else
     exit(0,"Build " + buildid + " is not affected.");
  }
}
