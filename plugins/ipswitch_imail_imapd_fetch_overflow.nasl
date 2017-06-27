#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21051);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2011/09/30 22:28:30 $");

  script_cve_id("CVE-2005-3526");
  script_bugtraq_id(17063);
  script_osvdb_id(23796);

  script_name(english:"Ipswitch IMail Server/Collaboration Suite IMAP FETCH Command Overflow");
  script_summary(english:"Checks version of Ipswitch IMAP server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch Collaboration Suite / IMail Secure
Server / IMail Server, commercial messaging and collaboration suites
for Windows. 

According to its banner, the version of Ipswitch Collaboration Suite /
IMail Secure Server / IMail Server installed on the remote host has a
buffer overflow issue in its IMAP server component. Using a
specially crafted FETCH command with excessive data, an authenticated
attacker can crash the IMAP server on the affected host, thereby
denying service to legitimate users, and possibly execute arbitrary
code as LOCAL SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-003.html");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics200603prem.asp");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics200603stan.asp");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/imsec200603.asp");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/im200603.asp");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2006.03 of the appropriate application.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/09");
  script_set_attribute(attribute:"patch_publication_date", value: "2006/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# There's a problem if the banner indicates it's < 9.03 (=2006.03).
banner = get_imap_banner(port:port);
if (!banner) exit(0);
if (egrep(pattern:"IMail ([0-8]\.|9.0[0-2])", string:banner)) security_warning(port);
