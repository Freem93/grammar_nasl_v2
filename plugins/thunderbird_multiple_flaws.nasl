#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14729);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904");
 script_bugtraq_id(11174, 11171, 11170);
 script_xref(name:"OSVDB", value:"9966");
 script_xref(name:"OSVDB", value:"9968");
 script_xref(name:"OSVDB", value:"10525");
 script_xref(name:"OSVDB", value:"10526");
 script_xref(name:"OSVDB", value:"10527");
 script_xref(name:"OSVDB", value:"10528");

 script_name(english:"Mozilla < 1.7.3 / Thunderbird < 0.8 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla and/or Thunderbird, an 
alternative mail user agent.

The remote version of this software is vulnerable to 
several flaws that could allow an attacker to execute 
arbitrary code on the remote host.

To exploit these flaws, an attacker would need to send a 
rogue email to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.3 or Thunderbird 0.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/29");
 script_cvs_date("$Date: 2012/08/03 21:46:19 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:thunderbird");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (!isnull(ver))
{
  if (
    ver[0] < 1 ||
    (
      ver[0] == 1 &&
      (
        ver[1] < 7 ||
        (ver[1] == 7 && ver[2] < 3)
      )
    )
  )  security_hole(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (!isnull(ver))
{
  if (ver[0] == 0 && ver[1] < 8)
    security_hole(get_kb_item("SMB/transport"));
}
