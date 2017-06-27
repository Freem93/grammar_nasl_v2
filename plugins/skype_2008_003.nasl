#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if (description)
{
  script_id(33125);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/06/06 20:52:31 $");

  script_cve_id("CVE-2008-1805", "CVE-2008-2545");
  script_bugtraq_id(29553);
  script_osvdb_id(46010);
  script_xref(name:"Secunia", value:"30547");

  script_name(english:"Skype file: URI Handling Security Bypass Arbitrary Code Execution (uncredentialed check)");
  script_summary(english:"Checks version of Skype");

  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a security policy bypass
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly uses
improper logic in its 'file:' URI handler when validating URLs by
failing to check for certain dangerous file extensions and checking
for others in a case-sensitive manner.

If an attacker can trick a user on the affected host into clicking on
a specially crafted 'file:' URI, this issue could be leveraged to
execute arbitrary code on the affected system subject to the user's
privileges.

Note this only affects Skype for Windows." );
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=711
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9341c10a" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493081/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-003.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype version 3.8.0.139 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "smb_nativelanman.nasl");
  script_require_keys("Services/skype");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# The flaw only affects Windows hosts.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS/smb");
  if (!os) exit(0, "The 'Host/OS/smb' KB item is missing.");
  if ("Windows" >!< os) exit(0, "The issue only affects Windows hosts.");
}


port = get_service(svc:"skype", exit_on_fail:TRUE);

# nb: "ts = 805281541" => "version = 3.8.0.139"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 805281541) security_hole(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
