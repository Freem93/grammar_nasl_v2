#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28228);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_bugtraq_id(26454, 26455);
  script_osvdb_id(39179, 39180);

  script_name(english:"Samba < 3.0.27 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote Samba server may be affected one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host contains a boundary error in the 'reply_netbios_packet()'
function in 'nmbd/nmbd_packets.c' when sending NetBIOS replies.
Provided the server is configured to run as a WINS server, a remote
attacker can exploit this issue by sending multiple specially crafted
WINS 'Name Registration' requests followed by a WINS 'Name Query'
request, leading to a stack-based buffer overflow. This could also
allow for the execution of arbitrary code.

There is also a stack buffer overflow in nmbd's logon request
processing code that can be triggered by means of specially crafted
GETDC mailslot requests when the affected server is configured as a
Primary or Backup Domain Controller. Note that the Samba security team
currently does not believe this particular issue can be exploited to
execute arbitrary code remotely.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-90/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483744");
  script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2007-4572.html");
  script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2007-5398.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483742");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483743");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba version 3.0.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/NativeLanManager");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
  if (ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-6])[^0-9]*$", string:lanman, icase:TRUE))
    security_hole(get_kb_item("SMB/transport"));
}
