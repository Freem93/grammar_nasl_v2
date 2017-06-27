#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25900);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4367");
  script_bugtraq_id(25331);
  script_osvdb_id(38124, 38125);

  script_name(english:"Opera < 9.23 Crafted Javascript Arbitrary Code Execution");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by an
arbitrary code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly allows
for execution of arbitrary code via specially crafted JavaScript if a
user can be tricked into visiting a malicious site." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/865/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/923/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.23 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/08/15");
 script_cvs_date("$Date: 2011/10/06 00:03:02 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[0-2])($|[^0-9]))")
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
