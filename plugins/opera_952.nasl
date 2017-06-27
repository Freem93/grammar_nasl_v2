#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33949);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2008-4195",
    "CVE-2008-4196",
    "CVE-2008-4197",
    "CVE-2008-4198",
    "CVE-2008-4199",
    "CVE-2008-4200",
    "CVE-2008-4293"
  );
  script_bugtraq_id(30768, 31183);
  script_osvdb_id(47688, 47689, 47690, 47691, 47692, 47693, 48719);
  script_xref(name:"Secunia", value:"31549");

  script_name(english:"Opera < 9.52 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
9.52 and thus reportedly affected by several issues :

  - Specially crafted URLs could start Opera in a way that
    would allow execution of arbitrary code.

  - Invalid checking of what frames a site can change,
    allowing a website to open pages from other sites.

  - An unspecified cross-site scripting issue.

  - Custom shortcuts and menu commands may pass parameters
    created from uninitialized memory.

  - Secure sites loading insecure content in a frame will
    cause Opera to incorrectly display the padlock icon.

  - Feed sources can link to a user's local disk, and
    appropriate JavaScript can detect if these files exist
    or not.

  - The page address may be changed when a user subscribes
    to a newsfeed subscription using the feed subscription
    button." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/892/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/893/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/894/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/895/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/896/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/897/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/900/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/952/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.52 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 79, 200, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/20");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([0-4][0-9]|5[0-1])($|[^0-9]))")
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
