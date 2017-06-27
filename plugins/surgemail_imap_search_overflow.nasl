#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25929);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-4377");
  script_bugtraq_id(25318);
  script_osvdb_id(37917);
  script_xref(name:"EDB-ID", value:"4287");

  script_name(english:"SurgeMail IMAP Server SEARCH Command Remote Buffer Overflow");
  script_summary(english:"Checks version in IMAP service banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of the
SurgeMail Mail Server older than 3.8k2 / 3.8m.  Such versions are
reportedly affected by a buffer overflow flaw in its IMAP service that
can be triggered using a specially crafted 'SEARCH' command.  An
authenticated attacker can leverage this issue to crash the remote
application and possibly execute arbitrary code remotely, subject to
the privileges under which the application runs." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/239" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb698652" );
 script_set_attribute(attribute:"see_also", value:"http://www.netwinsite.com/surgemail/help/updates.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeMail 3.8k2 / 3.8m or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/08/14");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
  pat = " IMAP [^ ]+ \(Version ([0-9]\.[0-9]+[a-z][0-9]*)-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's < 3.8k2 / 3.8m.
  if (ver && ver =~ "^([0-2]\.|3\.([0-7][a-z]|8([a-j]|k[01]?$)))") 
  {
    report = string(
      "According to its IMAP service banner, the remote is running SurgeMail\n",
      "version ", ver, "."
    );
    security_warning(port:port, extra:report);
  }
}
