#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34510);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238");
  script_bugtraq_id(31962);
  script_osvdb_id(49410, 49411);
  script_xref(name:"Secunia", value:"32419");

  script_name(english:"OpenOffice < 2.4.2 WMF and EMF File Handling Buffer Overflows");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program affected by multiple buffer
overflows." );
 script_set_attribute(attribute:"description", value:
"The version of OpenOffice 2.x installed on the remote host is earlier
than 2.4.2.  Such versions are affected by several issues :

  - Specially crafted WMF files can lead to heap-based
    overflows and arbitrary code execution (CVE-2008-2237).

  - Specially crafted EMF files can lead to heap-based 
    overflows and arbitrary code execution (CVE-2008-2238)." );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2008-2237.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2008-2238.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.4.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/29");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");
  exit(0);
}

#

build = get_kb_item("SMB/OpenOffice/Build");
if (build)
{
  matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
  if (!isnull(matches))
  {
    buildid = int(matches[2]);
    if (buildid > 8950 && buildid < 9364 && matches[1] !~ "^300m") security_hole(get_kb_item("SMB/transport"));
  }
}
