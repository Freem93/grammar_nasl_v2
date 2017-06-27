#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15432);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-0906");
 script_bugtraq_id(11166);
 script_xref(name:"OSVDB", value:"10559");

 script_name(english:"Mozilla Multiple Products XPInstall Arbitrary File Overwrite");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a web browser installed that has file
permissions set incorrectly." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla and/or Firefox, an alternative web 
browser.

The version of this software is prone to an improper file permission
setting. This flaw only exists if the browser is installed by the 
Mozilla Foundation package management, therefore, this alert might be 
a false positive.

A local attacker could overwrite arbitrary files or execute arbitrary
code in the context of the user running the browser." );
  # http://web.archive.org/web/20050404025219/http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:107
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25f8ca14" );
  # http://web.archive.org/web/20041013064553/http://www.suse.de/de/security/2004_36_mozilla.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b64dd06" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/13");
 script_cvs_date("$Date: 2013/03/28 21:38:35 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:firefox");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla/Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 if ( NASL_LEVEL >= 3206 )script_require_ports("Mozilla/Version", "Mozilla/Firefox/Version");
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
  if (ver[0] == 0)security_hole(get_kb_item("SMB/transport"));
}
