#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14181);
 script_version("$Revision: 1.26 $");

 script_cve_id("CVE-2004-0763", "CVE-2004-0764");
 script_bugtraq_id(10796, 10832);
 script_osvdb_id(8238, 8310, 8311);

 script_name(english:"Firefox < 1.0 Multiple Spoofing Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a web browser installed that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla and/or Firefox, an alternative web
browser. This web browser supports the XUL (XML User Interface
Language), a language designed to manipulate the user interface of the
browser itself.

Since XUL gives the full control of the browser GUI to the visited
websites, an attacker may use it to spoof a third-party website and,
therefore, pretend that the URL and Certificates of the website are
legitimate.

In addition to this, the remote version of this browser is vulnerable
to a flaw which may allow a malicious website to spoof security
properties such as SSL certificates and URIs." );
 script_set_attribute(attribute:"see_also", value:"http://www.nd.edu/~jsmith30/xul/test/spoof.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla/Firefox");
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
        (ver[1] == 7 && ver[2] < 2)
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
      (ver[1] == 9 && ver[2] < 3)
    )
  ) security_hole(get_kb_item("SMB/transport"));
}
