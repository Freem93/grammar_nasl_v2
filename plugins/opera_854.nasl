#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21221);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-1834");
  script_bugtraq_id(17513);
  script_osvdb_id(31744);

  script_name(english:"Opera < 8.54 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is prone to a buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera, an alternative web browser. 

The version of Opera installed on the remote host contains a buffer
overflow that can be triggered by a long value within a stylesheet
attribute.  Successful exploitation can lead to a browser crash and
possibly allow for the execution of arbitrary code subject to the
privileges of the user running Opera." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430876/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/854/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 8.54 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/13");
 script_cvs_date("$Date: 2016/05/12 14:46:30 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-7]\.|8\.([0-4][0-9]|5[0-3])($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
