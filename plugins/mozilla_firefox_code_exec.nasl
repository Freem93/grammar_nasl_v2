#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12642);
 script_version("$Revision: 1.25 $");

 script_cve_id("CVE-2004-0648");
 script_bugtraq_id(10681);
 script_osvdb_id(7595);

 script_name(english:"Mozilla Browsers shell: URI Arbitrary Command Execution");
 script_summary(english:"Determines the version of Mozilla/Firefox");

 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
a command execution vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is using Mozilla and/or Firefox, a web browser.
The remote version of this software contains a weakness that could
allow an attacker to execute arbitrary commands on the remote host." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Jul/421"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Jul/355"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://mozilla.org/security/shell.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.1 / Firefox 0.9.2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/07/07");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
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
        (ver[1] == 7 && ver[2] == 0 && ver[3] < 1)
      )
    )
  )  security_hole(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (
    ver[0] == 0 &&
    (
      ver[1] < 9 ||
      (ver[1] == 9 && ver[2] < 2)
    )
  ) security_hole(get_kb_item("SMB/transport"));
}
