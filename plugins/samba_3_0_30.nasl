#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32476);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2008-1105");
  script_bugtraq_id(29404);
  script_osvdb_id(45657);
  script_xref(name:"Secunia", value:"30228");

  script_name(english:"Samba < 3.0.30 receive_smb_raw Function Remote Buffer Overflow");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is reportedly affected by a boundary error in 'nmbd' within the
'receive_smb_raw' function in 'lib/util_sock.c' when parsing SMB
packets received in a client context. By sending specially crafted
packets to an 'nmbd' server configured as a local or domain master
browser, an attacker can leverage this issue to produce a heap-based
buffer overflow and execute arbitrary code with system privileges.

Note that Nessus has not actually tried to exploit this issue, verify
the remote 'nmbd' server's configuration, or determine if the fix has
been applied.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-20/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2008-1105.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/328");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.0.30 or later or apply the patch referenced
in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman) || "Samba " >!< lanman) exit(0);

if (ereg(pattern:"Samba 3\.0\.([0-9]|[12][0-9])[^0-9]*$", string:lanman, icase:TRUE))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Samba server appears to be :\n",
      "\n",
      "  ", lanman, "\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
