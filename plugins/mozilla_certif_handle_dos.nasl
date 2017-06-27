#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14668);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2004-0758");
 script_bugtraq_id(10703);
 script_osvdb_id(7939);

 script_name(english:"Mozilla Multiple Browsers CA Certificate SSL Page DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a web browser installed that is affected
by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla, an alternative web browser.

The Mozilla Personal Security Manager (PSM) contains a flaw
that may permit an attacker to silently import a certificate into
the PSM certificate store. This corruption may result in a denial
of SSL connections." );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=249004" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109900315219363&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/06/29");
 script_cvs_date("$Date: 2013/03/28 21:38:35 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla/Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 if ( NASL_LEVEL >= 3206 ) script_require_ports("Mozilla/Version", "Mozilla/Firefox/Version", "Mozilla/Thunderbird/Version");
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
        (ver[1] == 7 && ver[2] < 1)
      )
    )
  )  security_warning(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (
    ver[0] == 0 && 
    (
      ver[1] < 9 ||
      (ver[1] == 9 && ver[2] < 3)
    )
  )  security_warning(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (!isnull(ver))
{
  if (ver[0] == 0 && ver[1] < 8)
    security_warning(get_kb_item("SMB/transport"));
}
