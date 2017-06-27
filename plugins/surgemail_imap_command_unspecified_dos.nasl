#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if (description)
{
  script_id(33277);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-2859", "CVE-2008-7182");
  script_bugtraq_id(29805, 30000);
  script_osvdb_id(46434);
  script_xref(name:"EDB-ID", value:"5968");
  script_xref(name:"Secunia", value:"30739");

  script_name(english:"SurgeMail IMAP Service APPEND Command Remote DoS");
  script_summary(english:"Checks version in IMAP service banner");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of the
SurgeMail Mail Server older than 3.9g2.  The IMAP service in such
versions is reportedly affected by remote denial of service
vulnerabilities when handling an APPEND command with a large
parameter.  An authenticated attacker can leverage this issue to crash
the remote application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496482" );
 script_set_attribute(attribute:"see_also", value:"http://www.netwinsite.com/surgemail/help/updates.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeMail 3.9g2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/30");
 script_cvs_date("$Date: 2016/05/19 18:02:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


# Get the banner.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
banner = get_imap_banner(port:port);


# Check the version.
ver = NULL;

if (banner && " IMAP " >< banner && " (Version " >< banner)
{
  pat = " IMAP (\(C\) )?[^ ]+ \(Version ([0-9]\.[0-9]+[a-z][0-9]*)-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[2];
        break;
      }
    }
  }

  # There's a problem if it's < 3.9g2.
  if (ver && ver =~ "^([0-2]\.|3\.([0-8][a-z]|9([a-f]|g[01]?$)))") 
  {
    report = string(
      "\n",
      "Surgemail ", ver, " is currently installed on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
}
