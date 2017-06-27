#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(29250);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2012/02/09 20:24:55 $");

  script_cve_id("CVE-2007-5989");
  script_bugtraq_id(26748);
  script_osvdb_id(39170);

  script_name(english:"Skype skype4com URI Handler Remote Heap Corruption (uncredentialed check)");
  script_summary(english:"Checks version of Skype");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by a buffer overflow vulnerability" );
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host is vulnerable to a
heap overflow attack in the skype4com uri handler. 

To exploit this vulnerability, a remote attacker must trick a user on
the affected host into clicking on a specially crafted Skype URL." );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-070.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype release 3.6.0.216" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

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

# nb: "ts = 711112234" => "version = 3.6.0.216"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 711112234) security_hole(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
