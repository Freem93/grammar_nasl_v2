#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29253);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2007-6015");
  script_bugtraq_id(26791);
  script_osvdb_id(39191);

  script_name(english:"Samba < 3.0.28 send_mailslot Function Remote Buffer Overflow");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is reportedly affected by a boundary error in 'nmbd' within the
'send_mailslot' function. Provided the 'domain logons' option is
enabled in 'smb.conf', an attacker can leverage this issue to produce
a stack-based buffer overflow using a 'SAMLOGON' domain logon packet
in which the username string is placed at an odd offset and is
followed by a long 'GETDC' string.

Note that Nessus has not actually tried to exploit this issue nor
verify whether the 'domain logons' option has been enabled on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-99/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484818/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://us3.samba.org/samba/security/CVE-2007-6015.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba version 3.0.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

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
  if (ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-7])[^0-9]*$", string:lanman, icase:TRUE))
    security_hole(get_kb_item("SMB/transport"));
}
