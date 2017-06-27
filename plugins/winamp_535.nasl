#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25956);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/06/06 18:55:26 $");

  script_cve_id("CVE-2007-2498");
  script_bugtraq_id(23723);
  script_osvdb_id(34433);
  script_xref(name:"EDB-ID", value:"3823");

  script_name(english:"Winamp < 5.35 MP4 File Handling Buffer Overflow");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows.

The version of Winamp installed on the remote Windows host reportedly
contains a flaw involving its handling of 'MP4' files. If an attacker
can trick a user on the affected host into opening a specially crafted
MP4 file, this issue could be leveraged to execute arbitrary code on
the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp version 5.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/Winamp/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");


# Nullsoft issued a patch for 5.34 that we can't detect so we only
# run the check if reporting is paranoid.

if (report_paranoia < 2) audit(AUDIT_PARANOID);


# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client reports.

ver = get_kb_item("SMB/Winamp/Version");
if (ver && ver =~ "^([0-4]\.|5\.([0-2]\.|3\.[0-4]\.))")
  security_hole(get_kb_item("SMB/transport"));
