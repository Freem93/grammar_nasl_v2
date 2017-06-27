#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(21576);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2012/02/09 20:24:55 $");

  script_cve_id("CVE-2006-2312");
  script_bugtraq_id(18038);
  script_osvdb_id(25658);

  script_name(english:"Skype URI Handling Arbitrary File Download (uncredentialed check)");
  script_summary(english:"Checks version of Skype");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by an information disclosure
issue." );
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host reportedly may allow
a remote attacker to initiate a file transfer to another Skype user by
means of a specially crafted Skype URL." );
  script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2006-001.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 2.0.*.105 / 2.5.*.79 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/19");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
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

# nb: "ts = 605101300" => "version = 2.0.0.105"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 605101300) security_note(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
