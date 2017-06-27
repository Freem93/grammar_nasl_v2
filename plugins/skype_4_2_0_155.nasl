#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45060);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/05 04:45:41 $");

  script_bugtraq_id(38699);
  script_osvdb_id(62853);
  script_xref(name:"Secunia", value:"38908");

  script_name(english:"Skype skype: URI Handling /Datapath Argument Injection Settings Manipulation (uncredentialed check)");
  script_summary(english:"Checks Skype timestamp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Skype client is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its timestamp, the version of Skype installed on the
remote Windows host fails to sanitize input in its URI handler to its
'/Datapath' argument, which specifies the location of the Skype
configuration files and security policy.

If an attacker can trick a user on the affected system into clicking
on a specially crafted link, the client could be used on a Datapath
location on a remote SMB share.  In turn, this could lead to man-in-
the-middle attacks or the disclosure of sensitive information, such
as call history associated with the user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.security-assessment.com/files/advisories/Skype_URI_Handling_Vulnerability.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/510017/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.skype.com/WindowsSkype/ReleaseNotes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://share.skype.com/sites/garage/2010/03/10/ReleaseNotes_4.2.0.155.pdf"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Skype 4.2.0.155 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/03/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/10");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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

# nb: "ts = 1002211620" => "version = 4.2.0.152 / 4.2.0.155"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 1002211620) security_warning(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
