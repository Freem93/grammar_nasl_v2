#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62215);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2011-4313",
    "CVE-2012-0831",
    "CVE-2012-1172",
    "CVE-2012-1667",
    "CVE-2012-1823",
    "CVE-2012-2143",
    "CVE-2012-2311",
    "CVE-2012-2386",
    "CVE-2012-2688",
    "CVE-2012-3718",
    "CVE-2012-3720"
  );
  script_bugtraq_id(
    47545,
    50690,
    51954,
    53388,
    53403,
    53729,
    53772,
    54638,
    56243,
    56252
  );
  script_osvdb_id(
    72399,
    77159,
    79017,
    81426,
    81633,
    81791,
    82510,
    82609,
    84126,
    85647,
    85650
  );

  script_name(english:"Mac OS X 10.8.x < 10.8.2 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.8.x that is prior
to 10.8.2. The newer version contains multiple security-related fixes
for the following components :

  - BIND
  - Data Security
  - LoginWindow
  - Mobile Accounts
  - PHP"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5501");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


if (ereg(pattern:"Mac OS X 10\.8($|\.[0-1]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
