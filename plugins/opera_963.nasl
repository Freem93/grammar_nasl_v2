#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35185);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-5178", "CVE-2012-1251");
  script_bugtraq_id(32323, 32864, 32891);
  script_osvdb_id(49882, 82726);

  script_name(english:"Opera < 9.63 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.63
and thus reportedly affected by several issues :

  - It may be possible to execute arbitrary code on the
    remote system by manipulating certain text-area 
    contents. (920)

  - It may be possible to crash the remote browser using 
    certain HTML constructs or inject code under certain 
    conditions. (921)

  - It may be possible to trigger a buffer overflow, and
    potentially execute arbitrary code, by tricking an 
    user to click on a URL that contains exceptionally 
    long host names. (922)

  - While previewing news feeds, Opera does not correctly
    block certain scripted URLs. Such scripts, if not 
    blocked, may be able to subscribe a user to other 
    arbitrary feeds and view contents of the feeds to which
    the user is currently subscribed. (923)

  - By displaying content using XSLT as escaped strings, it 
    may be possible for a website to inject scripted
    markup. (924)

  - SSL server certificates are not properly validated due
    to an unspecified error. (CVE-2012-1251)" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/920" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/921" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/922" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/923" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/924" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/963/" );
 script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN39707339/index.html");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.63 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/16");
 script_cvs_date("$Date: 2013/06/04 00:44:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (
    ver[0] == 9 &&
    (
      ver[1]  < 63
    )
  )
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
