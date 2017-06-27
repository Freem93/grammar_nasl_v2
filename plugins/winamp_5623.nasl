#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57363);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2011-3834");
  script_bugtraq_id(51015);
  script_osvdb_id(77636, 77637, 77638);

  script_name(english:"Winamp < 5.623 Multiple Integer Overflows");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple integer overflow vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.623 and thus is reportedly affected by the following integer
overflow vulnerabilities :

  - An integer-overflow vulnerability exists in 'in_avi.dll'
    when allocating memory using the number of stream
    headers. An attacker can trigger a heap overflow by
    enticing an unsuspecting user to open a specially
    crafted AVI file.

  - An integer-overflow vulnerability exists in 'in_avi.dll'
    when parsing the 'RIFF INFO' chunk included in an AVI
    file. An attacker can exploit this issue by enticing an
    unsuspecting victim to open a specially crafted AVI
    file.

  - An integer-overflow vulnerability exists in 'in_avi.dll'
    when parsing song message data included in an Impulse
    Tracker (IT) file. Successful exploits will allow
    arbitrary code to run in the context of the application.
    Failed attacks will cause denial of service
    conditions.");

  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.623 (5.6.2.3199) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-81/");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=332010");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
fixed_version = "5.6.2.3199";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Winamp/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Winamp " + version + " install on the host is not affected.");
