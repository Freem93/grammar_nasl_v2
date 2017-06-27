#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16199);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2004-2384");
  script_bugtraq_id(9920);
  script_osvdb_id(20147);

  script_name(english:"Winamp < 5.03 Filename Handler Local Buffer Overflow");
  script_summary(english:"Determines the version of Winamp");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote application is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote host is using Winamp, a popular media player that handles
many files format (mp3, wavs and more...).

The remote version of this software is vulnerable to a local buffer
overrun when handling a large file name. This buffer overflow may
be exploited to execute arbitrary code on the remote host.

An attacker may exploit this flaw by sending a file with a long file
name to a victim on the remote host.  When the user attempts to open
this file using Winamp, a buffer overflow condition will occur."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Winamp 5.03 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2004/Mar/187'
  );

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");

 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/19");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
if (version =~ "^([0-4]\.|5\.0\.[0-3]\.)")
{
  if (report_verbosity > 0)
  {
    fixed_version = '5.03';

    path = get_kb_item("SMB/Winamp/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Winamp " + version + " is installed.");
