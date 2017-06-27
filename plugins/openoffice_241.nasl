#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33129);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-2152");
  script_bugtraq_id(29622);
  script_osvdb_id(46052);
  script_xref(name:"Secunia", value:"30599");

  script_name(english:"OpenOffice < 2.4.1 rtl_allocateMemory() Function Crafted Document Handling Integer Overflow");
  script_summary(english:"Checks version of OpenOffice"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program affected by an integer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of OpenOffice installed on the remote host reportedly
contains an integer overflow vulnerability in 'rtl_allocateMemory()',
a custom memory allocation function used by the application.  If an
attacker can trick a user on the affected system, he can leverage this
issue to execute arbitrary code subject to his privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b889d923" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493227/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2008-2152.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenOffice version 2.4.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/10");
 script_cvs_date("$Date: 2011/09/10 01:48:52 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:openoffice.org");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

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
    if (buildid < 9310) security_hole(get_kb_item("SMB/transport"));
  }
}
