#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25290);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-2809");
  script_bugtraq_id(24080);
  script_osvdb_id(36229);

  script_name(english:"Opera < 9.21 Transfer Manager Torrent File Handling Overflow");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is prone to a buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly contains
a buffer overflow vulnerability that can be triggered by a malicious
Torrent file.  Successful exploitation requires that a user on the
affected host right-click on the torrent entry in the transfer manager
rather than simply click on a torrent link and may allow a remote
attacker to execute arbitrary code subject to the privileges of the
user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45badbe6" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/May/354" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/860/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.21 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/21");
 script_cvs_date("$Date: 2016/11/02 14:37:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|20)($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
