#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(30206);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2008-0454", "CVE-2008-0582", "CVE-2008-0583");
  script_bugtraq_id(27338);
  script_osvdb_id(42863, 42864, 42865, 42868);

  script_name(english:"Skype Web Content Zone Multiple Field Remote Code Execution (uncredentialed check)");
  script_summary(english:"Checks version of Skype");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a remote code execution issue
through the web handler." );
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly may allow
a remote attacker to execute arbitrary code by enticing the user to
retrieve specially crafted we content through the skype interface." );
  script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-001-update2.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-002.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2008-001-update1.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 3.6.0.248 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

# nb: "ts = 802011429" => "version = 3.6.0.248"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 802011429) security_hole(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
