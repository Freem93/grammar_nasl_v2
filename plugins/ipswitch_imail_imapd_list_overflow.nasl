#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20320);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2011/09/12 01:34:03 $");

  script_cve_id("CVE-2005-2923");
  script_bugtraq_id(15753);
  script_osvdb_id(21499);

  script_name(english:"Ipswitch IMail Server IMAP LIST Command Remote Overflow DoS");
  script_summary(english:"Checks for LIST command denial of service vulnerability in Ipswitch IMAPD");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch Collaboration Suite or IMail
Server, commercial messaging and collaboration suites for Windows. 

The version of Ipswitch Collaboration Suite / IMail server installed
on the remote host contains an IMAP server that suffers from a denial
of service flaw.  Using a specially crafted LIST command of around
8000 bytes, an authenticated attacker can crash the IMAP server on the
affected host, thereby denying service to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60ba29e7");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics202.asp");
  script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/imail_professional/im822.asp");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch Collaboration Suite 2.02 / IMail 8.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# There's a problem if the banner indicates it's < 8.22.
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(pattern:"IMail ([0-7]\.|8.([01]|2[01])([^0-9]|$))", string:banner)
) {
  security_hole(port);
  exit(0);
}
