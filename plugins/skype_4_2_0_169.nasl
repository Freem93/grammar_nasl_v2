#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50597);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_bugtraq_id(38667);
  script_osvdb_id(62913);
  script_xref(name:"Secunia", value:"38875");

  script_name(english:"Skype Extras Manager (skypePM.exe) skype-plugin: URI Arbitrary XML File Deletion (uncredentialed check)");
  script_summary(english:"Checks Skype timestamp");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Skype client allows deletion of arbitrary XML files."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its timestamp, the version of Skype installed on the
remote host likely includes a version of the Skype Extras Manager
(skypePM.exe) that has a flaw in its handling of the 'skype-plugin:'
protocol.

If an attacker can trick a user on the affected system into clicking
on a specially crafted link, an arbitrary '.xml' file could be deleted
on the affected system subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-028/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Mar/115"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Skype 4.2.0.169 or later as that is reported to address
the issue."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

# nb: "ts = 1005131530" => "version = 4.2.0.169"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts > 0 && ts < 1005131530) security_warning(port);
else exit(0, "The Skype client listening on port "+port+" is not affected based on its timestamp ("+ts+").");
