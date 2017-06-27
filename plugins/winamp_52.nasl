#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20973);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/06/18 11:04:23 $");

  script_cve_id("CVE-2006-0708", "CVE-2006-0720");
  script_bugtraq_id(16623, 16785);
  script_osvdb_id(23265, 23525, 30142);
  script_xref(name:"EDB-ID", value:"26245");

  script_name(english:"Winamp < 5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application that is vulnerable to denial of service
attacks is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
crashes if the user tries to open an M3U file with a long filename. 

In addition, it reportedly contains a buffer overflow flaw that can be
exploited using a specially crafted M3U file to either crash the
application or possibly even execute arbitrary code remotely.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424903/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425888/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp version 5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("smb_func.inc");

# Check version of Winamp.

ver = get_kb_item("SMB/Winamp/Version");
if (
  ver &&
  ver =~ "^([0-4]\.|5\.[01]\.)"
) {
  security_hole(kb_smb_transport());
}
