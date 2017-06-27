#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67207);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/07 02:06:54 $");

  script_cve_id("CVE-2013-4694", "CVE-2013-4695");
  script_bugtraq_id(60883, 60886);
  script_osvdb_id(94739, 94740, 94741);
  script_xref(name:"EDB-ID", value:"26557");
  script_xref(name:"EDB-ID", value:"26558");
  script_xref(name:"EDB-ID", value:"27874");

  script_name(english:"Winamp < 5.64 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than 5.64
and is, therefore, reportedly affected by the following 
vulnerabilities :

  - A buffer overflow exists in the 'ml_local.dll' when
    passed GUI search fields.

  - A buffer overflow exists in the 'gen_jumpex.dll' when
    handling Skins directory names.

  - Invalid pointer dereference vulnerabilities exist in
    the 'gen_ff.dll' library when loading the links.xml.

Successful exploitation can allow arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://security.inshell.net/advisory/51");
  script_set_attribute(attribute:"see_also", value:"http://security.inshell.net/advisory/52");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=364291");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/help/Version_History");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.64 (5.6.4.3418) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
path = get_kb_item_or_exit("SMB/Winamp/Path");

fixed_version = "5.6.4.3418";
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Winamp", version, path);
