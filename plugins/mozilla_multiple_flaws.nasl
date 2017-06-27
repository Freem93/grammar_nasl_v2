#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14728);
 script_version("$Revision: 1.23 $");
 script_cve_id(
   "CVE-2004-0904", 
   "CVE-2004-0905", 
   "CVE-2004-0906", 
   "CVE-2004-0908"
 );
 script_bugtraq_id(
   11194, 
   11192, 
   11169, 
   11171, 
   11177, 
   11179 
 );
 script_osvdb_id(9965, 10524, 10525, 10559);

 script_name(english:"Mozilla Browsers Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Mozilla");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The remote host is using Mozilla and/or Firefox, a web browser.

The remote version of this software is vulnerable to several flaws
that could allow an attacker to execute arbitrary code on the remote
host, get access to content of the user clipboard or, perform
a cross-domain cross-site scripting attack.

A remote attacker could exploit these issues by tricking a user
into viewing a malicious web page." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.3 / Firefox 0.10.0 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/14");
 script_cvs_date("$Date: 2013/04/02 21:54:25 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:firefox");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:thunderbird");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:navigator");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 if ( NASL_LEVEL >= 3206 ) script_require_ports("Mozilla/Version", "Mozilla/Firefox/Version");
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

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (ver[0] == 0 && ver[1] < 10)
    security_hole(get_kb_item("SMB/transport"));
}
