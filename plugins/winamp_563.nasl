#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59756);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2012-3889", "CVE-2012-3890", "CVE-2012-4045");
  script_bugtraq_id(54131);
  script_osvdb_id(83097, 83098);
  script_xref(name:"Secunia", value:"46624");

  script_name(english:"Winamp < 5.63 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.63 and is, therefore, reportedly affected by the following
vulnerabilities :

  - A memory corruption error exists in 'in_mod.dll'
    related to input validation when handling 'Impulse
    Tracker' (IT) files.

  - Heap-based buffer overflows exist related to
    'bmp.w5s' when handling 'BI_RGB' and 'UYVY' data in AVI
    files. Processing decompressed TechSmith Screen Capture
    Codec (TSCC) data in AVI files can also trigger a heap-
    based buffer overflow.

Successful exploitation can allow arbitrary code execution."
  );

  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.63 (5.6.3.3234) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=345684");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/help/Version_History");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
fixed_version = "5.6.3.3234";

path = get_kb_item("SMB/Winamp/Path");
if (isnull(path)) path = 'n/a';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

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
