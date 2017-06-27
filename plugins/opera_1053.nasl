#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46204);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/01/03 22:36:51 $");

  script_cve_id("CVE-2010-1728");
  script_bugtraq_id(39855);
  script_osvdb_id(64160);
  script_xref(name:"Secunia", value:"39590");

  script_name(english:"Opera < 10.53 Asynchronous Content Modification Uninitialized Memory Access");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that may allow code
execution.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.53.  Such versions are potentially affected by the following 
issue :

  - Multiple asynchronous calls to a script that modifies 
    document contents can be abused to reference an
    uninitialized value, leading to an application crash
    or possibly allowing execution of arbitrary code. 
    (953)"
  );
  # http://web.archive.org/web/20100504014234/http://h.ackack.net/?p=258
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d143f98e");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/953/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1053/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.53 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 53)
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Opera ' + version_report + ' is currently installed on the remote host.\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
