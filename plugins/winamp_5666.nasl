#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71787);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 16:51:15 $");

  script_bugtraq_id(63914);

  script_name(english:"Winamp < 5.666 Multiple Memory Corruptions");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.  The
version of Winamp installed on the remote host is a version prior to
5.666.  It is, therefore, reportedly affected by the following
vulnerabilities :

  - A memory corruption error exists in 'in_midi.dll' when
    processing specially crafted '.kar' files.

  - A memory corruption error exists in 'libmp4v2.dll' due
    to a NULL pointer dereference when processing specially
    crafted files.

An attacker could exploit these vulnerabilities to cause a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/help/Version_History");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=373755");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.666 (5.6.6.3516) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
path = get_kb_item_or_exit("SMB/Winamp/Path");

fixed_version = "5.6.6.3516";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Winamp", version, path);
